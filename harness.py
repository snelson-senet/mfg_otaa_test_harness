from lorawan import packet 
from lorawan import region
from lorawan import crypto
from lorawan import semtech_packet_forward_server 
import json
import sys
import csv
import os
import binascii
import logging
import random
import glob
from collections import namedtuple

# Harness Version
version="1.0.0"
TEST_HARNESS_NAME = "Test Harness - Gateway Over the Air Activation"

# Tuple of device network session.  Session does not include the nwkskey
# because it is not needed by the test harness 
JoinSession = namedtuple('JoinSession', ['appnonce', 'devaddr', 'nwkskey'])

# Dictionary of Applications indexed by JoinEui
appdb = {}

# custom log level for test results 
TEST = logging.WARNING + 1
logging.addLevelName(TEST, 'TEST')
def testlog(self, message, *args, **kws):
    self.log(TEST, message, *args, **kws)
logging.Logger.test = testlog

logger = logging.getLogger('th')
logger.setLevel(logging.DEBUG)

#Logger format
logfmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# test logging 
th = logging.FileHandler('test.log')
th.setLevel(TEST)
th.setFormatter(logfmt)
logger.addHandler(th)

# console logging
ch = logging.StreamHandler()
ch.setFormatter(logfmt)
logger.addHandler(ch)

CONF_DIR = 'conf'
TEST_CONF_FILE_DEFAULT = 'test_harness.conf'
SERVER_PORT_DEFAULT = 1780
LORAWAN_REGION_DEFAULT = "US915"

# Packet Forwarder initialized in main 
forwarder = None
# LoRaWAN Region 
lw_region = None

# DevAddr generator
def generate_devaddr():
    for devaddr in range(0xFFFF0000,0xFFFFFFFF):
        yield devaddr 
devaddr_generator = generate_devaddr()

class Device(object):

    def __init__(self, deveui, appkey):
        self.__appkey = appkey
        self.__deveui = deveui
        self.__joined = False
        self.__joining = False
        self.__session = JoinSession(None,None,None)
        self.__altrDr  = 0

    @property
    def appkey(self):
        return self.__appkey

    @property
    def deveui(self):
        return self.__deveui

    @property
    def joining(self):
        return self.__joining

    @joining.setter
    def joining(self, joining):
        self.__joining = joining
        if joining:
            self.__joined = False
    @property
    def joined(self):
        return self.__joined 

    @joined.setter
    def joined(self, joined):
        self.__joined = joined
        if self.__joined:
            self.__joining = False

    @property
    def session(self):
        return self.__session

    @session.setter
    def session(self, session):
        self.__session = session

    def get_join_rxslot(self):
        rxslot = 1 if self.__altrDr & 1 == 0 else 2
        self.__altrDr = self.__altrDr + 1
        return rxslot

class Application(object):
    DEFAULT_NETID = 0

    def __init__(self, joineui, netid=DEFAULT_NETID):
        self.__joineui = joineui
        self.__devices = {}
        self.__netid = netid
        self.__devaddr2device = {}

    @property
    def joineui(self):
        return self.__joineui

    @property 
    def netid(self):
        return self.__netid

    @property    
    def devices(self):
        return self.__devices

    def import_devices(self, joineui, device_file):
        try:
            with open(device_file) as csvfile:
                reader = csv.DictReader(csvfile)
                if 'DEVEUI' not in reader.fieldnames or 'APPKEY' not in reader.fieldnames:
                    logger.error("Missing field names in f=%s" % device_file)
                    sys.exit(-1)

                row_nb = 0
                for row in reader:
                    row_nb = row_nb + 1
                    try:
                        deveui = row['DEVEUI'].strip()
                        appkey = row['APPKEY'].strip()
                    except:
                        logger.critical("read file %s invalid row %d" % (device_file, row_nb))
                        sys.exit(-1)

                    # convert to binary 
                    try:
                        bin_deveui = binascii.unhexlify(deveui)
                    except:
                        bin_deveui = None 
                    if bin_deveui is None or len(bin_deveui) != 8:
                        logger.error("invalid deveui=%s in f=%s entry=%d" % (deveui, device_file, row_nb))
                        sys.exit(-1)

                    try:
                        bin_appkey = binascii.unhexlify(appkey)
                    except:
                        bin_appkey = None 
                    if bin_appkey is None or len(bin_appkey) != 16:
                        logger.error("invalid appkey=%s in f=%s entry=%d" % (appkey, device_file, row_nb))
                        sys.exit(-1)
                    
                    if bin_deveui not in self.__devices:
                        self.__devices[bin_deveui] = Device(bin_deveui, bin_appkey)
                    else:
                        logger.error("Duplicate entries for deveui=%s found in f=%s" % (deveui, device_file))
                        sys.exit(-1)
        except IOError:
            logger.critical("%s not found" % device_file)
            sys.exit(-1)

        logger.log(TEST, "joineui=%s imported %d devices" % (joineui, self.nb_devices))

    @property
    def nb_devices(self):
        return len(self.__devices)

    def new_device_session(self, device, netid, devnonce):
        devaddr = device.session.devaddr
        if devaddr is None:
            devaddr = devaddr_generator.next() 
        appnonce = random.randint(1, 0xFFFFFF)
        nwkskey = crypto.compute_nwk_skey(appnonce, netid, devnonce, device.appkey)
        logger.debug("new session devaddr=%04X, anonce=%04X, devnonce=%02X, nwkskey=%s" 
                % (devaddr, appnonce, devnonce, binascii.hexlify(nwkskey)))
        device.session = JoinSession(appnonce, devaddr, nwkskey)
        self.__devaddr2device[devaddr] = device

    def deveui2device(self, deveui):
        return self.__devices.get(deveui, None)

    def devaddr2device(self, devaddr):
        return self.__devaddr2device.get(devaddr, None)
    
def rx_handler(pkt):
    if pkt.is_join_request():
        join_request_handler(pkt)
    else:
        uplink_handler(pkt)

def join_request_handler(pkt):
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("rxpk: %s" % pkt.rxpk)

    try:
        joineui = pkt.get_AppEui()
        app = appdb[joineui]
    except:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("joineui=%s not in test database" % binascii.hexlify(joineui))
        return

    deveui = pkt.get_DevEui()
    device = app.deveui2device(deveui)
    if device is not None:
        send_join_accept(app, device, pkt)
    else:
       logger.debug("deveui=%s not in joineui=%s test database" % (binascii.hexlify(deveui), binascii.hexlify(joineui)))

def send_join_accept(application, device, jreq):
    txtmst = None 
    # Selct rx slot
    dr = lw_region.sf2txdr(jreq.datr)
    rxslot = device.get_join_rxslot()
    if 1 == rxslot:
        rxconf = lw_region.get_rx1_conf(jreq.freq, dr)
        txtmst = jreq.tmst + lw_region.JOIN_RX1_DELAY * 1000000 
    elif 2 == rxslot:
        rxconf = lw_region.get_rx2_conf()
        txtmst = jreq.tmst + lw_region.JOIN_RX2_DELAY * 1000000 

    if txtmst is None:
        logger.error("join accept transmit timestamp not set")
        return

    deveui_s = binascii.hexlify(device.deveui).upper()
    channel = lw_region.tx_channel(jreq.freq, dr)
    logger.test("joineui=%s, deveui=%s : status=Join-request received on channel=%d, DR%d" 
                    % (application.joineui, deveui_s, channel, dr))

    # Initialize new session
    application.new_device_session(device, application.netid, jreq.DevNonce) 
    device.joining = True

    # Send join accept frame
    jacc = packet.encode_join_accept_frame(device.appkey, device.session.appnonce, application.netid, device.session.devaddr)
    if forwarder.transmit(jacc, txtmst, rxconf, jreq):
        logger.test("joineui=%s, deveui=%s : status=Join-accept on RX%d sent to packet forwarder" % (application.joineui, deveui_s, rxslot))

def uplink_handler(pkt):
    for joineui in appdb:
        app = appdb[joineui]
        device = appdb[joineui].devaddr2device(pkt.DevAddr)
        if device is not None and device.joining:
            validate_uplink_after_join_accept(app, device, pkt)

def validate_uplink_after_join_accept(app, device, pkt):
    mic = crypto.compute_uplink_mic(bytes(pkt.PHYPayload[:-4]), device.session.nwkskey, pkt.DevAddr, pkt.FCnt)
    if pkt.MIC == mic:
        device.joined = True
        logger.test("joineui=%s, deveui=%s : status=OTAA Success" % (app.joineui, binascii.hexlify(device.deveui)))
    else:
        logger.test("joineui=%s, deveui=%s : status=MIC check failed" % (app.joineui, binascii.hexlify(device.deveui)))

def read_conf():
    conf_file = CONF_DIR + '/' + TEST_CONF_FILE_DEFAULT
    test_conf = {}
    app_conf  = {}

    # Read global test configuration
    try:
        with open(conf_file, 'r') as json_file:
            test_conf = json.load(json_file)
    except IOError:
        logger.critical("%s not found" % conf_file)
        sys.exit(-1)
    except ValueError as jex:
        logger.critical("%s: JSON error: %s" % (conf_file, jex))
        sys.exit(-1)

    # Import device configuration
    for filename in glob.glob(CONF_DIR + '/*.csv'):
        base = os.path.basename(filename)
        joineui = os.path.splitext(base)[0]
        try:
            bjoineui = binascii.unhexlify(joineui)
        except:
            logger.critical("csv file=%s is not a valid join eui" % filename)
            sys.exit(-1)

        # initialize application
        joineui = joineui.upper()
        application = Application(joineui)
        # import device
        application.import_devices(joineui, filename)
        app_conf[bjoineui] = application

    return test_conf, app_conf 

def run():
    global appdb
    global lw_region
    global forwarder

    logger.test("Gateway Over the Air Activation Test Harness Version %s" % version)
    test_conf, appdb = read_conf()

    # Logging debug to file 
    if 'debug_log' in test_conf:
        dfh = logging.FileHandler(test_conf['debug_log'])
        dfh.setLevel(logging.DEBUG)
        dfh.setFormatter(logfmt)
        logger.addHandler(dfh)

    # packet forwarder server configuration
    server_port = test_conf.get('server_port', SERVER_PORT_DEFAULT)
    region_name = test_conf.get('region', LORAWAN_REGION_DEFAULT)
    # start server 
    lw_region = region.get(region_name)
    forwarder = semtech_packet_forward_server.Server("localhost", server_port, region_name)
    forwarder.run(rx_handler) 
    logger.critical("Unexpected server exit!")
    sys.exit(-1)

if __name__ == '__main__':
    run()