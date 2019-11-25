import crypto
import binascii
import struct

JOIN_REQ_MTYPE = 0
JOIN_ACCEPT_MTYPE = 1 
UNCONFIRMED_UL_MTYPE = 2 
UNCONFIRMED_DL_MTYPE = 3 
CONFIRMED_UL_MTYPE = 4 
CONFIRMED_DL_MTYPE = 5
RFU_MTYPE = 6
PROPRIETARY_MTYPE = 7

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
       self.DevNonce = None
       self.AppKey = None
       self.DevAddr = None
       self.FCnt = None
       self.FCtrl = None

       if PHYPayload is not None:
          self.initialize_from_phypayload(PHYPayload)

       if self.MType is None:
           print("Received MType == None")

   def initialize_from_phypayload(self, PHYPayload):
       self.PHYPayload = bytearray(PHYPayload)
       self.MType = self.PHYPayload[0] >> 5
       if self.MType == JOIN_REQ_MTYPE:
           self.initialize_from_join_request(self.PHYPayload[1:])
       elif self.MType in [UNCONFIRMED_UL_MTYPE, CONFIRMED_UL_MTYPE] :
           self.initialize_from_uplink(self.PHYPayload[1:])

   def initialize_from_join_request(self, MACPayload):
       self.MACPayload = MACPayload
       self.AppEui = str(MACPayload[7::-1] )
       self.DevEui = str(MACPayload[15:7:-1])
       self.DevNonce = str(MACPayload[17:15:-1])

   def initialize_from_uplink(self, MACPayload):
       self.DevAddr, self.FCtrl, self.FCnt = struct.unpack("<IBH", bytes(MACPayload[:7]))

   def get_MType(self):
        return self.MType

   def get_AppEui(self):
       return self.AppEui

   def get_DevEui(self):
       return self.DevEui

   @property
   def MIC(self):
       return bytes(self.PHYPayload[-4:])

   def get_MType_name(self):
        return MType.get(self.MType, self.MType)

   def is_join_request(self):
        return self.MType == JOIN_REQ_MTYPE 

   def is_join_accept(self):
        return self.MType == JOIN_ACCEPT_MTYPE 

   def pkt_len(self):
       return len(self.PHYPayload)

   def to_string(self): 
       if self.is_join_request():
           return "{} DevEui:{}, AppEui:{}".format(self.get_MType_name(), to_eui_format(self.DevEui), to_eui_format(self.AppEui))
       elif self.is_join_accept():
           return "%s PHYPayload: %s" % (self.get_MType_name(), binascii.hexlify(str(self.PHYPayload)))
       else:
           return "{}".format(self.get_MType_name())

   def compute_mic(self, buffer, appkey):
        return crypto.aes_cmac(buffer, appkey)


def encode_join_accept_frame(appkey, appnonce, netid, devaddr, dlsettings=8, rxdelay=1, cflist=None):

    mtype = struct.pack("B", JOIN_ACCEPT_MTYPE<<5) 

    macpayload = struct.pack("<6BIBB", netid>>16 & 0xff, netid>>8 & 0xff, netid & 0xff,
        appnonce>>16 & 0xff, appnonce>>8 & 0xff, appnonce & 0xff, devaddr, dlsettings, rxdelay)

    mic = struct.pack("<I", crypto.aes_cmac(mtype + macpayload, appkey))
    encrypted = crypto.aes128_decrypt(macpayload + mic, appkey)
    return mtype + encrypted