from Cryptodome.Hash import CMAC 
from Cryptodome.Cipher import AES

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

def toEuiFormat(eui):
    return '-'.join('{:02x}'.format(x) for x in eui)


class packet:
   def  __init__(self, PHYPayload):
       self.PHYPayload = None
       self.MType = None 
       self.DevEui = None
       self.AppEui = None
       self.DevNonce = None
       self.MIC = None

       if PHYPayload is not None:
          self.initialize_from_phypayload(PHYPayload)

       if self.MType is None:
           print("Received MType == None")

   def initialize_from_phypayload(self, PHYPayload):
       self.PHYPayload = PHYPayload
       self.MType = PHYPayload[0] >> 5
       if self.MType == JOIN_REQ_MTYPE:
           self.initialize_from_join_request(PHYPayload[1:])

   def initialize_from_join_request(self, MACPayload):
       self.MACPayload = MACPayload
       self.AppEui = MACPayload[7::-1] 
       self.DevEui = MACPayload[15:7:-1] 
       self.DevNonce = MACPayload[17:15:-1]
       self.MIC = MACPayload[21:17:-1]

   def getMTypeName(self):
        return MType.get(self.MType, self.MType)

   def isJoinRequest(self):
        return self.MType == JOIN_REQ_MTYPE 

   def toString(self): 
       if self.isJoinRequest():
           return "{} DevEui:{}, AppEui:{}".format(self.getMTypeName(), toEuiFormat(self.DevEui), toEuiFormat(self.AppEui))
       else:
           return "{}".format(self.getMTypeName())

   def generate_join_accept(self, appkey):
    
    def compute_mic(self, appkey):
        if self.MType == JOIN_ACCEPT_MTYPE:
            return self.compute_join_accept_mic(appkey)
        elif self.MType == UNCONFIRMED_UL_MTYPE or self.MType == CONFIRMED_UL_MTYPE:
            return self.compute_ul_mic(appkey)
        else:
            return None

    def compute_join_accept_mic(self, appkey):
        # cmac = aes128_cmac(AppKey, MHDR|APPNONCE|NetID|DevAddr|RFU|RXDELAY|CFLIST)

def from_wire(PHYPayload):
    return packet(PHYPayload)