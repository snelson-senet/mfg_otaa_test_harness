import ctypes
import os
import platform
import struct
import sys
import logging

logger = logging.getLogger("harness.lwcrypto")

def initialize_crypto_extension():
    # C extension shared libray path
    mydir = os.path.dirname(os.path.abspath(__file__))
    machine = platform.machine()
    libpath = os.path.join(mydir,'extension/build/', machine, "bin", "crypto.so")
    try:
        return ctypes.CDLL(libpath)
    except:
        logger.critical("lorawan crypto c extension %s not found" % libpath)
        sys.exit(-1)

crypto = initialize_crypto_extension()

# uint32_t aes_cmac( const uint8_t *buffer, uint16_t size, const uint8_t *key);
crypto.aes_cmac.argtypes = (ctypes.c_char_p, ctypes.c_uint16, ctypes.c_char_p) 
crypto.aes_cmac.restype = ctypes.c_uint32 

# void encrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint8_t *encBuffer );
crypto.aes128_encrypt.argtypes = (ctypes.c_char_p, ctypes.c_uint16, ctypes.c_char_p, ctypes.c_char_p)

# void decrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint8_t *decBuffer );
crypto.aes128_decrypt.argtypes = (ctypes.c_char_p, ctypes.c_uint16, ctypes.c_char_p, ctypes.c_char_p)

# void compute_app_skey(const uint8_t *key,  uint32_t appnonce, uint32_t netid, uint16_t devnonce, uint8_t *nwkSKey);
crypto.compute_app_skey.argtypes = (ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint16, ctypes.c_char_p)

# void compute_nwk_skey(const uint8_t *key,  uint32_t appnonce, uint32_t netid, uint16_t devnonce, uint8_t *nwkSKey);
crypto.compute_nwk_skey.argtypes = (ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint16, ctypes.c_char_p)

# uint32_t compute_uplink_mic(const uint8_t *buffer, uint16_t size, const uint8_t *key, uint32_t devaddr,  uint32_t fcnt)
crypto.compute_uplink_mic.argtypes = (ctypes.c_char_p, ctypes.c_uint16, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32)
crypto.compute_uplink_mic.restype = ctypes.c_uint32

def aes_cmac(buffer, key):
    size = len(buffer)
    c_buf = ctypes.c_char_p(buffer)
    c_key = ctypes.c_char_p(key)
    mic = crypto.aes_cmac(c_buf, size, c_key)
    return mic 

def aes128_encrypt(buffer, key):
    size = len(buffer)
    c_buf = ctypes.c_char_p(buffer)
    c_key = ctypes.c_char_p(key)

    out = ctypes.create_string_buffer(size) 
    crypto.aes128_encrypt(c_buf, size, c_key, out)
    return out.raw

def aes128_decrypt(buffer, key):
    size = len(buffer)
    c_buf = ctypes.c_char_p(buffer)
    c_key = ctypes.c_char_p(key)

    out = ctypes.create_string_buffer(size) 
    crypto.aes128_decrypt(c_buf, size, c_key, out)
    return out.raw 

def compute_uplink_mic(buffer, key, devaddr, fcnt):
    size = len(buffer)
    c_buf = ctypes.c_char_p(buffer)
    c_key = ctypes.c_char_p(key)
    mic = crypto.compute_uplink_mic(c_buf, size, c_key, devaddr, fcnt)
    return mic 

def compute_app_skey(appnonce, netid, devnonce, key):
    c_key = ctypes.c_char_p(key)
    appskey = ctypes.create_string_buffer(16)
    crypto.compute_app_skey(c_key, appnonce, netid, devnonce, appskey)
    return appskey.raw

def compute_nwk_skey(appnonce, netid, devnonce, key):
    c_key = ctypes.c_char_p(key)
    nwkskey = ctypes.create_string_buffer(16)
    crypto.compute_nwk_skey(c_key, appnonce, netid, devnonce, nwkskey)
    return nwkskey.raw