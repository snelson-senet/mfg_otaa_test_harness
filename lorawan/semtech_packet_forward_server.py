import socket
import json
import binascii
import struct
import region
import packet

VERSIONS = [1,2]

PUSH_DATA = 0
PUSH_ACK = 1
PULL_DATA = 2
PULL_RESP = 3
PULL_ACK = 4

INVALID_TIMESTAMP = -1
INVALID_FREQ = -1 
INVALID_DR = -1

SOCK_RX_CNT = 'sock_rx'
PUSH_DATA_CNT = 'push_data'
PULL_RESP_CNT = 'pull_resp'

class RxPacket(packet.Packet):
    def __init__(self, version, rxpk):
         self._version = version
         self.rxpk = rxpk
         self.pr_token = 0
         data = self.rxpk["data"].decode('base64')
         packet.Packet.__init__(self, data)

    @property
    def freq(self):
        return self.rxpk['freq']

    @property
    def datr(self):
        return self.rxpk['datr']

    @property
    def tmst(self):
        return self.rxpk['tmst']

    @property
    def version(self):
        return self._version 

    def next_pull_response_token(self):
        self.pr_token = self.pr_token + 1
        return self.pr_token 

class Server:
    def __init__(self, server_host, server_port, region_name, discard_mtypes=None):
        self.server_host = server_host
        self.server_port = server_port
        self.counter = {SOCK_RX_CNT:0, PUSH_DATA_CNT:0, PULL_RESP_CNT:0}
        self.rx_handler = None
        self.region = region.get(region_name)
        self.discard_mtypes = discard_mtypes
        self.socket_up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_down = self.socket_up
        self.socket_up.bind((self.server_host, self.server_port))
        self.pull_dest_addr = None
        self.push_dest_addr = None

    def incr(self, counter):
        cnt = self.counter[counter] 
        self.counter[counter] = cnt + 1

    def run(self, rx_handler):
        self.rx_handler = rx_handler

        print("Semtech Packet Forwarder: Host:%s Port:%d" % (self.server_host, self.server_port))
        while True:
            data, addr = self.socket_up.recvfrom(1024)
            self.receive(data, addr)

    def receive(self, packet, addr):
        self.incr(SOCK_RX_CNT)
        version, = struct.unpack('=B',packet[0])
        if version not in VERSIONS:
             print("SMTCPF RX: Bad version %d" % version)
             return

        # Get mesage header
        try:
            _token, cmd, _mac = struct.unpack('<HBQ', packet[1:12])
        except:
            print("SMTCPF RX: Message size=%d too small" % len(packet))
            return

        # Process message 
        if cmd == PUSH_DATA:
            self.push_dest_addr = addr
            self.push_data(packet, version)
        elif cmd == PULL_DATA:
            self.pull_dest_addr = addr
            self.pull_data(packet)
        else:
            print("SMTCPF RX: Drop message id=%d" % cmd)

    def push_data(self, packet, version):
        # Parse JSON message
        try:
            data = json.loads(packet[12:])
        except:
            print("PUSH_DATA: JSON decode error!")
            return

        self.incr(PUSH_DATA_CNT) 
        # Send ack
        ack = packet[:3] + struct.pack('B', PUSH_ACK)
        self.socket_down.sendto(ack, self.push_dest_addr)
        print("PUSH_ACK: %s:%d" %(self.push_dest_addr[0], self.push_dest_addr[1]))

        # process packets
        rxpk = data.get('rxpk', None)
        if rxpk is not None:
            for pkt in rxpk:
                pkt = RxPacket(version, pkt)
                if (self.discard_mtypes == None) or (pkt.get_MType() not in self.discard_mtypes):
                    self.rx_handler(pkt)

    def pull_data(self, pull_data_pkt):
        ack = pull_data_pkt[:3] + struct.pack('B', PULL_ACK)
        self.socket_down.sendto(ack, self.pull_dest_addr)
        print("PULL_ACK: %s:%d" %(self.pull_dest_addr[0], self.pull_dest_addr[1]))

    def transmit(self, frame, tmst, rxconf, push_pkt):
        # base64 encode frame and strip that damn invalid newline character that python adds for giggles!!
        b64_data = frame.encode("base64").rstrip()

        token = push_pkt.next_pull_response_token()
        tx_hdr = struct.pack('<BHB', push_pkt.version, token, PULL_RESP)
        tx_json = {}
        tx_json['freq'] = rxconf.freq
        tx_json['datr'] = self.region.dr2sf(rxconf.dr)
        tx_json['codr'] = self.region.coderate
        tx_json['tmst'] = tmst
        tx_json['modu'] ='LORA'
        tx_json['ipol'] ='true'
        tx_json['rfch'] = 0 
        tx_json['ant']  = 0
        tx_json['powe'] = 20
        tx_json['data'] = b64_data
        tx_json['size'] = len(frame)

        tx_json_s = json.dumps({'txpk':tx_json})
        tx_msg  = tx_hdr + tx_json_s 
        if self.pull_dest_addr is not None:
            bytes_sent = self.socket_down.sendto(tx_msg, self.pull_dest_addr)
            print("PULL_RESP: %s:%d bytes_sent=%d, json=%s" % (self.pull_dest_addr[0], self.pull_dest_addr[1], bytes_sent, tx_json_s))
            self.incr(PULL_RESP_CNT) 
        else:
            print("PULL_RESP: destination address not set (PULL_DATA message not received from client")

    def send_join_accept(self, rxpkt, key, rxslot, netid, devaddr, dlsettings, rxdelay, appnonce, cflist=None):
        rx_tmst = rxpkt.tmst
        tx_tmst = INVALID_TIMESTAMP

        if 1 == rxslot:
            dr = self.region.sf2txdr(rxpkt.datr)
            rxconf = self.region.get_rx1_conf(rxpkt.freq, dr)
            tx_tmst = rx_tmst + self.region.JOIN_RX1_DELAY * 1000000 
        elif 2 == rxslot:
            rxconf = self.region.get_rx2_conf()
            tx_tmst = rx_tmst + self.region.JOIN_RX2_DELAY * 1000000 

        if tx_tmst == INVALID_TIMESTAMP:
            print("SMTCPF Tx JoinAccept: Invalid transmit timestamp")
            return

        # Get join accept frame
        if appnonce is None:
            appnonce = 1
        jacc = packet.encode_join_accept_frame(key, appnonce, netid, devaddr, dlsettings, rxdelay, cflist)
        # base64 encode frame and strip that damn invalid newline character that python adds for giggles!!
        b64_data = jacc.encode("base64").rstrip()

        """
        PULL_RESP format
        Bytes  | Function
        0      | protocol version = 2
        1-2    | random token
               | PULL_RESP identifier 0x03
        4-end  | JSON object, starting with {, ending with }, see section 6
        """
        token = rxpkt.next_pull_response_token()
        tx_hdr = struct.pack('<BHB', rxpkt.version, token, PULL_RESP)
        tx_json = {}
        tx_json['freq'] = rxconf.freq
        tx_json['datr'] = self.region.dr2sf(rxconf.dr)
        tx_json['codr'] = self.region.coderate
        tx_json['tmst'] = tx_tmst
        tx_json['modu'] ='LORA'
        tx_json['ipol'] ='true'
        tx_json['rfch'] = 0 
        tx_json['ant']  = 0
        tx_json['powe'] = 20
        tx_json['data'] = b64_data
        tx_json['size'] = len(jacc)

        tx_json_s = json.dumps({'txpk':tx_json})
        tx_msg  = tx_hdr + tx_json_s 
        if self.pull_dest_addr is not None:
            bytes_sent = self.socket_down.sendto(tx_msg, self.pull_dest_addr)
            print("PULL_RESP: %s:%d bytes_sent=%d, json=%s" % (self.pull_dest_addr[0], self.pull_dest_addr[1], bytes_sent, tx_json_s))
            self.incr(PULL_RESP_CNT) 
        else:
            print("PULL_RESP: destination address not set (PULL_DATA message not received from client")