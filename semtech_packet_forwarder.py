import socket
import json
import binascii
import lorawan_packet
import struct


PROTOCOL_V2 = 2
PUSH_DATA = 0
PUSH_ACK = 1
PULL_DATA = 2
PULL_ACK = 4


class Protocol:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.ip, self.port))

        while True:
            data, _addr = sock.recvfrom(1024)
            self.receive(data)

    def receive(self, packet):
        version,  = struct.unpack('=B',packet[0])
        if version != PROTOCOL_V2:
             return

        token, cmd, mac = struct.unpack('<HBQ', packet[1:12])
        # version = int(header[:2],16)
        # version = header[0]
        # if version != PROTOCOL_V2:
        #    return

        # token = int(header[2:6],16)
        # cmd = int(header[6:8],16)
        # eui = header[8:]

        if cmd == PUSH_DATA:
            try:
                push_data = json.loads(packet[12:])
            except:
                print("JSON decode error!")
            self.receivePushData(token, push_data)


    def receivePushData(self, token, push_data):
        rxpk = push_data.get('rxpk', None)
        if rxpk is not None:
            for pkt in rxpk:
                b64 = pkt["data"].decode('base64')
                unpack_fmt = '{}B'.format(len(b64))
                payload = struct.unpack(unpack_fmt,b64)
                pkt = lorawan_packet.from_wire(payload)
                print(pkt.toString())
                if pkt.isJoinRequest():
                    self.processJoinRequest(pkt)

    def processJoinRequest(self, pkt):
        pass