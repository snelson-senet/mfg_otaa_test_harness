import socket
import json
import binascii
import struct
import region
import packet
import logging

logger = logging.getLogger('test_harness.packet_fwd_server')
logger.setLevel(logging.DEBUG)

VERSIONS = [1,2]

PUSH_DATA = 0
PUSH_ACK = 1
PULL_DATA = 2
PULL_RESP = 3
PULL_ACK = 4
TX_ACK = 5

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
        try:
            return self.rxpk['freq']
        except:
            logger.warning("rxpk no freq attribute")
            return None

    @property
    def datr(self):
        try:
            return self.rxpk['datr']
        except:
            logger.warning("rxpk no datr attribute")
            return None
          

    @property
    def tmst(self):
        try:
            return self.rxpk['tmst']
        except:
            logger.warning("rxpk no tmst attribute")
            return None

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

        logger.info("server on %s:%d" % (self.server_host, self.server_port))
        while True:
            data, addr = self.socket_up.recvfrom(1024)
            self.receive(data, addr)

    def receive(self, msg, addr):
        self.incr(SOCK_RX_CNT)
        version, = struct.unpack('=B',msg[0])
        if version not in VERSIONS:
             logger.warning("received bad version %d" % version)
             return

        # Get mesage header
        try:
            _token, cmd, _mac = struct.unpack('<HBQ', msg[1:12])
        except:
            logger.warning("message size %d is too small" % len(msg))
            return

        # Process message 
        if cmd == PUSH_DATA:
            self.push_dest_addr = addr
            self.push_data(msg, version)
        elif cmd == PULL_DATA:
            self.pull_dest_addr = addr
            self.pull_data(msg)
        elif cmd == TX_ACK:
            self.tx_ack(msg)
        else:
            logger.debug("unhandled message command=%d" % cmd)

    def push_data(self, msg, version):
        # Parse JSON message
        try:
            data = json.loads(msg[12:])
        except:
            logger.error("push_data JSON decode error")
            return

        self.incr(PUSH_DATA_CNT) 
        # Send ack
        ack = msg[:3] + struct.pack('B', PUSH_ACK)
        self.socket_down.sendto(ack, self.push_dest_addr)
        # logger.debug("push_ack address=%s:%d" %(self.push_dest_addr[0], self.push_dest_addr[1]))

        # process packets
        rxpk = data.get('rxpk', None)
        if rxpk is not None:
            for pkt in rxpk:
                pkt = RxPacket(version, pkt)
                if (self.discard_mtypes == None) or (pkt.get_MType() not in self.discard_mtypes):
                    self.rx_handler(pkt)

    def pull_data(self, msg):
        ack = msg[:3] + struct.pack('B', PULL_ACK)
        self.socket_down.sendto(ack, self.pull_dest_addr)
        # logger.debug("pull_ack address=%s:%d" %(self.pull_dest_addr[0], self.pull_dest_addr[1]))

    def tx_ack(self, msg):
        status = 'None'
        # Check for downlink status indication 
        try:
            data = json.loads(msg[12:])
            txpk_ack = data.get("txpk_ack", None)
            if txpk_ack:
                status = txpk_ack['error']
        except:
            pass

        logger.debug("downlink status=%s" % status) 
         

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
            self.incr(PULL_RESP_CNT) 
            msg_bytes = len(tx_msg)
            bytes_sent = self.socket_down.sendto(tx_msg, self.pull_dest_addr)
            if bytes_sent != msg_bytes: 
                logger.error("socket sendto %s:%d bytes sent=%d != msg size=%d" % (self.pull_dest_addr[0], self.pull_dest_addr[1], bytes_sent, msg_bytes))
                return False
            elif logger.isEnabledFor(logging.DEBUG):
                logger.debug("txpk=%s" %  tx_json_s)
            return True 
        else: # no client address condition can occur if pull response occurs before client's first pull request
            logger.warning("pull response client address not set") 
            return False