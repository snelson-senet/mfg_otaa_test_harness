from lorawan import packet 
from lorawan import region
from lorawan import semtech_packet_forward_server 
import json
import getopt, sys
import csv
import os
import binascii

DEBUG = True

CONF_DIR = 'conf'
TEST_CONF_FILE_DEFAULT = 'test_harness.conf'
SERVER_HOST_DEFAULT = 'localhost'
SERVER_PORT_DEFAULT = 1780
LORAWAN_REGION_DEFAULT = "US915"

test_conf = None
appeui_conf  = None
device_db = None
Forwarder = None

def debug_log(s):
    if DEBUG:
        print(s)

def rx_handler(pkt):
    app = None
    device = None

    if pkt.is_join_request():
        try:
            appeui = pkt.get_AppEui()
            app = appeui_conf[appeui]
        except:
             debug_log("JREQ: APPEUI %s not configured" % binascii.hexlify(appeui))
             return

        try:
            deveui = pkt.get_DevEui()
            device = app[deveui]
        except:
             debug_log("JREQ: APPEUI %s, DEVEUI %s not configured" % (binascii.hexlify(appeui), binascii.hexlify(deveui)))
             return

        print("JREQ: APPEUI %s, DEVEUI %s" % (binascii.hexlify(appeui), binascii.hexlify(deveui)))
        send_join_accept(app, device, pkt)

def send_join_accept(application, device, jreq):
    txtmst = None 

    # Selct rx slot
    rxslot = 1
    if 1 == rxslot:
        dr = LwRegion.sf2txdr(jreq.datr)
        rxconf = LwRegion.get_rx1_conf(jreq.freq, dr)
        txtmst = jreq.tmst + LwRegion.JOIN_RX1_DELAY * 1000000 
    elif 2 == rxslot:
        rxconf = LwRegion.get_rx2_conf()
        txtmst = jreq.tmst + LwRegion.JOIN_RX2_DELAY * 1000000 

    if txtmst is None:
        print("send_join_accept: No transmit timestamp!")
        return

    # Get join accept frame
    appkey = device['APPKEY']
    netid = 0
    devaddr = 1
    dlsettings = 8
    appnonce = 1
    rxdelay = 1
    jacc = packet.encode_join_accept_frame(appkey, appnonce, netid, devaddr, dlsettings, rxdelay)

    # Send frame  
    Forwarder.transmit(jacc, txtmst, rxconf, jreq)


def display_help():
    print("Test Harness Help")
    print("--conf <filename>")
    print("--help")

def read_test_configuration(conf_file):
    json_conf = {}
    device_conf = {}
    try:
        with open(conf_file, 'r') as json_file:
            json_conf = json.load(json_file)
            for appeui in json_conf['appeui']:
                key = binascii.unhexlify(appeui)
                device_conf[key] = read_appeui_config(appeui)
    except IOError:
        print("%s not found" % conf_file)
        sys.exit(-1)
    except ValueError as jex:
        print("%s: JSON error: %s" % (conf_file, jex))
        sys.exit(-1)

    return json_conf, device_conf

def read_appeui_config(appeui):
    devices = {}
    try:
        filename = CONF_DIR + '/' + appeui + '.csv'
        with open(filename) as csvfile:
            reader = csv.DictReader(csvfile)
            row_nb = 0
            required = ['DEVEUI', 'APPKEY']
            unhexlify = required

            for row in reader:
                row_nb = row_nb + 1
                devconf = {}
                for key in required: 
                    try:
                        value = row[key]
                    except:
                        print("%s:  row %d missing %s" % key)
                        sys.exit(-1)

                    if key in unhexlify:
                        value = binascii.unhexlify(value)

                    if key is 'DEVEUI':
                        deveui = value 
                    else:
                        devconf[key] = value 

                devices[deveui] = devconf

        print("%s: device count=%d" % (appeui, len(devices)))
        return devices

    except IOError as ioex:
        print("%s: IOError: %s" %  (filename, ioex))
        sys.exit(-1)

if __name__ == "__main__":
    shortopts = []
    longopts = ["help", "conf="]
    test_conf_file = CONF_DIR + '/' + TEST_CONF_FILE_DEFAULT

    # Get command line options
    try:
        arguments, values = getopt.getopt(sys.argv[1:], shortopts, longopts)
    except getopt.error as err:
        print(str(err))
        sys.exit(2)

    for option, value in arguments:
        if option in ("--conf"):
            test_conf_file = value
        elif option in ("--help"):
            display_help()
            sys.exit(0)

    # Read test configuration 
    test_conf, appeui_conf = read_test_configuration(test_conf_file)

    # Forwarding server configuration
    server_host = test_conf.get('server_host', SERVER_HOST_DEFAULT)
    server_port = test_conf.get('server_port', SERVER_PORT_DEFAULT)
    lwregion = test_conf.get('region', LORAWAN_REGION_DEFAULT)
    # Process join requests (MType=0) only 
    discard_mtypes = range(1,8)

    # Start server 
    LwRegion = region.get(lwregion)
    Forwarder = semtech_packet_forward_server.Server(server_host, server_port, lwregion, discard_mtypes)
    Forwarder.run(rx_handler) 
    # Does not return
    print("Unexpected server exit!")
    sys.exit(-1)
    
