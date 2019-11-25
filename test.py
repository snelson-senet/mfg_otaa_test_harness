import harness
import socket
import lorawan 
import binascii
import random
import json

test_conf = None
server_socket = None
server_addr = None
lw_region = None

push_data_header = bytes(bytearray([2,1,2,0,1,2,3,4,5,6,7,8]))

def send2server(data):
    server_socket.sendto(data, server_addr)

def send_join_request(joineui, device) :
    deveui = binascii.hexlify(device.deveui)

    devnonce = random.randint(1,0xFFFF)
    print("send_join_rquest: joineui=%s, deveui=%s, devnonce=%04x" %(joineui, deveui, devnonce))
    frame = lorawan.packet.encode_join_request_frame(joineui, deveui, devnonce, device.appkey)
    print("JREQ: %s" % binascii.hexlify(frame))

    rxpkt = {}
    rxpkt['data'] = frame.encode("base64").strip()
    rxpkt['tmst'] = 1000000
    rxpkt['freq'] = 902.3
    rxpkt['datr'] = lw_region.dr2sf(0)
    json_data = {"rxpk": [rxpkt]}
    print(json.dumps(json_data))
    send2server(push_data_header + json.dumps(json_data))

def test_app(app):
    print("test app %s" % app.joineui)
    for deveui in app.devices:
        send_join_request(app.joineui, app.devices[deveui])

if __name__ == '__main__':
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    test_conf, app_conf = harness.read_conf()
    region_name = test_conf.get('region', "US915")
    lw_region = lorawan.region.get(region_name)

    server_addr = ("localhost", test_conf['server_port'])
    for joineui in app_conf: 
        test_app(app_conf[joineui])