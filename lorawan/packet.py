import crypto
import binascii
import struct
import logging

JOIN_REQ_MTYPE = 0
JOIN_ACCEPT_MTYPE = 1 
UNCONFIRMED_UL_MTYPE = 2 
UNCONFIRMED_DL_MTYPE = 3 
CONFIRMED_UL_MTYPE = 4 
CONFIRMED_DL_MTYPE = 5
RFU_MTYPE = 6
PROPRIETARY_MTYPE = 7

logger = logging.getLogger('harness.lwpacket')
logger.setLevel(logging.DEBUG)

MType = {JOIN_REQ_MTYPE:'Join Request', JOIN_ACCEPT_MTYPE:'Join Accept', 
         UNCONFIRMED_UL_MTYPE :'Unconfirmed Data Up', UNCONFIRMED_DL_MTYPE :'Unconfirmed Data Down', 
         CONFIRMED_UL_MTYPE:'Confirmed Data Up', CONFIRMED_DL_MTYPE:'Confirmed Data Down', 
         RFU_MTYPE :'RFU', PROPRIETARY_MTYPE :'Proprietary'}

def to_eui_format(eui):
    return '-'.join('{:02x}'.format(x) for x in eui)

class Packet(object):
   def  __init__(self, PHYPayload = None):
       self.PHYPayload = None
       self.MType = None 
       self.DevEui = None
       self.AppEui = None
       self.AppKey = None
       self.DevAddr = None
       self.DevNonce = None
       self.FCnt = None
       self.FCtrl = None
       self.__valid = False

       if PHYPayload is not None:
          self.initialize_from_phypayload(PHYPayload)

       if self.MType is None:
           print("Received MType == None")

   def initialize_from_phypayload(self, PHYPayload):
       self.PHYPayload = bytearray(PHYPayload)
       self.MType = self.PHYPayload[0] >> 5
       if self.MType == JOIN_REQ_MTYPE:
           self.__valid = self.initialize_from_join_request(self.PHYPayload[1:])
       elif self.MType in [UNCONFIRMED_UL_MTYPE, CONFIRMED_UL_MTYPE] :
           self.__valid = self.initialize_from_uplink(self.PHYPayload[1:])

   def initialize_from_join_request(self, MACPayload):
       self.MACPayload = MACPayload
       try:
           self.AppEui = bytes(MACPayload[7::-1] )
           self.DevEui = bytes(MACPayload[15:7:-1])
           self.DevNonce = struct.unpack("<H",bytes(MACPayload[16:18]))[0]
           return True
       except:
           logger.warning("decode join request failed")
           return False

   def initialize_from_uplink(self, MACPayload):
       try:
           self.DevAddr, self.FCtrl, self.FCnt = struct.unpack("<IBH", bytes(MACPayload[:7]))
           return True
       except:
           logger.warning("decode uplink failed")
           return False

   def get_MType(self):
        return self.MType if self.valid else None

   def get_AppEui(self):
       return self.AppEui

   def get_DevEui(self):
       return self.DevEui if self.valid else None

   @property
   def valid(self):
       return self.__valid

   @property
   def MIC(self):
       mic = None
       if self.valid:
           mic, = struct.unpack("<I", bytes(self.PHYPayload[-4:]))
       return mic

   def get_MType_name(self):
        return MType.get(self.MType, self.MType)

   def is_join_request(self):
        return self.MType == JOIN_REQ_MTYPE if self.valid else False

   def is_join_accept(self):
        return self.MType == JOIN_ACCEPT_MTYPE  if self.valid else False

   def pkt_len(self):
       return len(self.PHYPayload) if self.valid else 0


def encode_join_accept_frame(appkey, appnonce, netid, devaddr, dlsettings=8, rxdelay=1, cflist=None):
    mtype = struct.pack("B", JOIN_ACCEPT_MTYPE<<5) 
    macpayload = struct.pack("<6BIBB", appnonce & 0xff, (appnonce>>8) & 0xff, (appnonce>>16) & 0xff,
                                       netid & 0xff, (netid>>8) & 0xff, (netid>>16) & 0xff, 
                                       devaddr, dlsettings, rxdelay)
    mic = struct.pack("<I", crypto.aes_cmac(mtype + macpayload, appkey))
    encrypted = crypto.aes128_decrypt(macpayload + mic, appkey)
    return mtype + encrypted

def encode_join_request_frame(joineui, deveui, devnonce, appkey):
    data = struct.pack("B", JOIN_REQ_MTYPE<<5) + binascii.unhexlify(joineui)[::-1] + binascii.unhexlify(deveui)[::-1] + struct.pack("<H", devnonce)
    mic = crypto.aes_cmac(data, appkey)
    return data + struct.pack("<I",mic)
