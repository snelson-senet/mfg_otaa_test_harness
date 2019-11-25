from collections import namedtuple
import logging

logger = logging.getLogger('test_harness.lorawan.region')

RxConf = namedtuple('RxConf', ['freq', 'dr'])

def get_us915_region():
    return US915Region()

SUPPORTED = {'US915': get_us915_region}

class Region(object):
    INVALID_FREQ = -1
    INVALID_DR = -1
    JOIN_RX1_DELAY = 5
    JOIN_RX2_DELAY = 6

    def __init__(self, region_name, coderate, rx1freqs, rx1_dr_offset, rx2conf, dr2sf, sf2txdr):
        self.region = SUPPORTED.get(region_name,None)
        assert self.region != None, "Unknown Region %s " % region_name
        self.rx2conf = rx2conf
        self.rx1freqs = rx1freqs
        self.rx1_dr_offset = rx1_dr_offset
        self.nb_rx1freqs = len(rx1freqs)
        self.dr2sf_table = dr2sf
        self.sf2txdr_map = sf2txdr
        self.coderate = coderate 

        # SF to DR map
        self.sf2dr_map = {}
        for i in range(0, len(dr2sf)):
            self.sf2dr_map[dr2sf[i]] = i

    def get_rx1_conf(self, tx_freq, tx_dr, rx1_dr_offset=0):
        try:
          chnl = self.tx_channel(tx_freq, tx_dr) % self.nb_rx1freqs 
          rx_dr = self.rx1_dr_offset[tx_dr][rx1_dr_offset]
          freq  = self.rx1freqs[chnl]
          return RxConf(freq=freq, dr=rx_dr)
        except:
            logger.error("REGION: get_rx1_config failed")
            return None 

    def get_rx2_conf(self):
        return self.rx2conf

    def dr2sf(self, dr):
        try:
            return self.dr2sf_table[dr]
        except:
            return None

    def sf2txdr(self, sf):
        try:
            return self.sf2txdr_map[sf]
        except:
             return 
      
    def tx_channel(self, freq_mhz, datarate):
        """ To be implemented by the region """
        return None

class US915Region(Region):
    def __init__(self):
        dr2sf = ["SF10BW125", "SF9BW125", "SF8BW125", "SF7BW125", "SF8BW500",
                 None,None,None,
                 "SF12BW500", "SF11BW500","SF10BW500","SF9BW500", "SF8BW500", "SF7BW500"]

        sf2txdr = {"SF10BW125":0, "SF9BW125":1, "SF8BW125":2, "SF7BW125":3, "SF8BW500":4}

        rx1_dr_offset =[[10,9,8,8], [11,10,9,8], [12,11,10,9], [13,12,11,10], [13,13,12,11]]
        rx1_freqs = [ round(923.3 + (i *.6), 2) for i in range(0, 8)]
        Region.__init__(self, 'US915', '4/5', rx1_freqs, rx1_dr_offset, RxConf(freq=923.3,dr=8), dr2sf, sf2txdr)

    def tx_channel(self, freq_mhz, datarate):
        if datarate in [0,1,2,3]:
            return int((freq_mhz  - 902.3) / .2) 
        elif datarate == 4:
            return 64 + int((freq_mhz  - 903.0) / 1.6) 
        else:
            return None
       

def get(region_name):
    if region_name in SUPPORTED:
        return SUPPORTED[region_name]()
    else:
        return None