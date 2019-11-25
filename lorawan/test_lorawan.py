import unittest
import crypto
import packet
import region
import binascii

class TestLoRaWAN(unittest.TestCase):

    def test_mic(self):
        #RFC 4493 NIST AES-CMAC Test Vectors
        key = binascii.unhexlify('2b7e151628aed2a6abf7158809cf4f3c')
        tv= [('', 0x29691dbb), 
             ('6bc1bee22e409f96e93d7e117393172a',0xb4160a07),
             ('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411',0x4767a6df),
             ('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',0xbfbef051)]

        for data, expected in tv:
            bdata = binascii.unhexlify(data)
            computed = crypto.aes_cmac(bdata, key)
            print("AES-CMAC computed=%08x, expected=%08x" % (computed, expected))
            self.assertTrue(computed == expected)

    def test_encrypt(self):
        data = binascii.unhexlify('FFEEDDCCBBAA99887766554433221100')
        key  = binascii.unhexlify('00112233445566778899AABBCCDDEEFF')
        crypto.aes128_encrypt(data, key)

    def test_decrypt(self):
        data = binascii.unhexlify('FFEEDDCCBBAA99887766554433221100')
        key  = binascii.unhexlify('00112233445566778899AABBCCDDEEFF')
        crypto.aes128_decrypt(data, key)

    def test_lorawan_packet_join_request(self):
        PHYPayload = binascii.unhexlify('00efbe0100000c250003030000010c25008e4aa15c1e3c')
        p = packet.Packet(PHYPayload)
        self.assertTrue(p.is_join_request())

        PHYPayload = binascii.unhexlify('20efbe0100000c250003030000010c25008e4aa15c1e3c')
        p = packet.Packet(PHYPayload)
        self.assertFalse(p.is_join_request())

    def test_lorawan_packet_join_accept(self):
        appkey = binascii.unhexlify('00112233445566778899AABBCCDDEEFF')
        expected = "2000a7a47881fd814024d3d420bacfa308"
        appnonce = 0x01020304
        netid = 0xaabbccdd 
        devaddr = 0xdeadbeef 
        dlsettings = 8
        rxdelay = 1
        frame = packet.encode_join_accept_frame(appkey, appnonce, netid, devaddr, dlsettings, rxdelay)
        hex_frame = binascii.hexlify(frame) 
        print("test_lorawan_packet_join accept: frame=%s, expected=%s" % (hex_frame, expected))
        self.assertTrue(binascii.hexlify(frame) == expected)


    def test_get_us915region(self):
        r = region.get("US915")
        self.assertTrue(r != None)

    def test_region_rx2(self):
        expected = (923.3, 8)
        r = region.get("US915")
        rx2  = r.get_rx2_conf()
        self.assertTrue(rx2 == expected)

    def test_region_rx1(self):
        tx_dr  = [0,1,2,3]
        rx1_dr = [10, 11, 12, 13]
        rx1_freqs = [ round(923.3 + (i * .6),2) for i in range(0, 8)]
        r = region.get("US915")

        for chnl in range(2,63):
            tx_freq = round(902.3 + (chnl * .2), 1)
            for dr in tx_dr:
                rx1 = r.get_rx1_conf(tx_freq, dr)
                self.assertTrue(rx1[0] == rx1_freqs[chnl % 8])
                self.assertTrue(rx1[1] == rx1_dr[dr])

    def test_region_dr2sf(self):
        r = region.get("US915")
        dr2sf =  dr2sf = ["SF10BW125", "SF9BW125", "SF8BW125", "SF7BW125", "SF8BW500",
                 None,None,None,
                 "SF12BW500", "SF11BW500","SF10BW500","SF9BW500", "SF8BW500", "SF7BW500"]

        for dr in range(0,len(dr2sf)):
            sf = r.dr2sf(dr)
            self.assertTrue(sf == dr2sf[dr])

if __name__ == '__main__':
    unittest.main()
