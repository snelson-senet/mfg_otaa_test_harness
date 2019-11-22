from lorawan import packet 
from lorawan import region
from lorawan import semtech_packet_forward_server 
import json
import getopt, sys
import csv
import os
import binascii
import logging
import random
from collections import namedtuple

# Test Harness Version
MAJOR_VERSION = 1
MINOR_VERSION = 0
TEST_HARNESS_NAME = "Test Harness - Gateway Over the Air Activation"

JoinSession = namedtuple('JoinSession', ['appnonce', 'devaddr'])

# Dictionary of Applications indexed by JoinEui
AppDb = {}

# custom log level for test results 
TEST = logging.WARNING + 1
logging.addLevelName(TEST, 'TEST')
def testlog(self, message, *args, **kws):
    self.log(TEST, message, *args, **kws)
logging.Logger.test = testlog

logger = logging.getLogger('test_harness')
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
SERVER_HOST_DEFAULT = 'localhost'
SERVER_PORT_DEFAULT = 1780
LORAWAN_REGION_DEFAULT = "US915"

# Packet Forwarder initialized in main 
Forwarder = None

# DevAddr generator
def generate_devaddr():
    for devaddr in range(0xFFFF0000,0xFFFFFFFF):
        yield devaddr 
devaddr_generator = generate_devaddr()

class Device(object):
    DEVICE_STATE_JOINING = 1 
    DEVICE_STATE_JOINED  = 2

    def __init__(self, deveui, appkey):
        self.__appkey = appkey
        self.__deveui = deveui
        self.__joined = False
        self.__joining = False
        self.__session = JoinSession(None,None)
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

    def import_devices(self, device_file):
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
        logger.info("imported joineui %s device count=%d" % (self.__joineui, len(self.__devices)))

    def new_device_session(self, device):
        devaddr = device.session.devaddr
        if devaddr is None:
            devaddr = devaddr_generator.next() 
        appnonce = random.randint(1, 0xFFFFFF)
        device.session = JoinSession(appnonce, devaddr)
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
        app = AppDb[joineui]
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
    dr = LwRegion.sf2txdr(jreq.datr)
    rxslot = device.get_join_rxslot()
    if 1 == rxslot:
        rxconf = LwRegion.get_rx1_conf(jreq.freq, dr)
        txtmst = jreq.tmst + LwRegion.JOIN_RX1_DELAY * 1000000 
    elif 2 == rxslot:
        rxconf = LwRegion.get_rx2_conf()
        txtmst = jreq.tmst + LwRegion.JOIN_RX2_DELAY * 1000000 

    if txtmst is None:
        logger.error("join accept transmit timestamp not set")
        return

    deveui_s = binascii.hexlify(device.deveui).upper()
    channel = LwRegion.tx_channel(jreq.freq, dr)
    logger.test("joineui=%s, deveui=%s : status=Join-request received on channel=%d, DR%d" 
                    % (application.joineui, deveui_s, channel, dr))

    # Initialize new session
    application.new_device_session(device) 
    device.joining = True

    # Send join accept frame
    jacc = packet.encode_join_accept_frame(device.appkey, device.session.appnonce, application.netid, device.session.devaddr)
    if Forwarder.transmit(jacc, txtmst, rxconf, jreq):
        logger.test("joineui=%s, deveui=%s : status=Join-accept on RX%d sent to packet forwarder" % (application.joineui, deveui_s, rxslot))

def uplink_handler(pkt):
    # logger.debug("uplink devaddr %x fcntup=%d" % (pkt.DevAddr, pkt.FCnt))
    for joineui in AppDb:
        app = AppDb[joineui]
        device = AppDb[joineui].devaddr2device(pkt.DevAddr)
        if device is not None and device.joining:
            device.joined = True
            logger.test("joineui=%s, deveui=%s : status=OTAA Success" % (app.joineui, binascii.hexlify(device.deveui)))
            return

def initialize_test():
    conf_file = CONF_DIR + '/' + TEST_CONF_FILE_DEFAULT
    test_conf = {}
    try:
        with open(conf_file, 'r') as json_file:
            test_conf = json.load(json_file)
            for jeui in test_conf['joineui']:
                jeui = jeui.strip()
                try:
                    bin_jeui = binascii.unhexlify(jeui)
                except:
                    logger.critical("%s: join eui %s not hexdecimal representation" % jeui)
                    sys.exit(-1)
                # initialize application
                application = Application(jeui.upper())
                filename = CONF_DIR + '/' + jeui +  '.csv'
                # import device
                application.import_devices(filename)
                AppDb[bin_jeui] = application
    except IOError:
        logger.critical("%s not found" % conf_file)
        sys.exit(-1)
    except ValueError as jex:
        logger.critical("%s: JSON error: %s" % (conf_file, jex))
        sys.exit(-1)
    return test_conf 


version="1.0.0"
logger.test("Gateway Over the Air Activation Test Harness Version %s" % version)

test_conf = initialize_test()

# Logging debug to file 
if 'debug_log' in test_conf:
     dfh = logging.FileHandler(test_conf['debug_log'])
     dfh.setLevel(logging.DEBUG)
     dfh.setFormatter(logfmt)
     logger.addHandler(dfh)

# packet forwarder server configuration
server_host = test_conf.get('server_host', SERVER_HOST_DEFAULT)
server_port = test_conf.get('server_port', SERVER_PORT_DEFAULT)
lwregion = test_conf.get('region', LORAWAN_REGION_DEFAULT)
# start server 
LwRegion = region.get(lwregion)
Forwarder = semtech_packet_forward_server.Server(server_host, server_port, lwregion)
Forwarder.run(rx_handler) 
logger.critical("Unexpected server exit!")
sys.exit(-1)