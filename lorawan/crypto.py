import ctypes
import os
import platform

# C extension shared libray path
mydir = os.path.dirname(os.path.abspath(__file__))
machine = platform.machine()
libpath = os.path.join(mydir,'extension/build/', machine, "bin", "crypto.so")
crypto = ctypes.CDLL(libpath)

# uint32_t aes_cmac( const uint8_t *buffer, uint16_t size, const uint8_t *key);
crypto.aes_cmac.argtypes = (ctypes.c_char_p, ctypes.c_uint16, ctypes.c_char_p) 
crypto.aes_cmac.restype = ctypes.c_uint32 

# void encrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint8_t *encBuffer );
crypto.aes128_encrypt.argtypes = (ctypes.c_char_p, ctypes.c_uint16, ctypes.c_char_p, ctypes.c_char_p)

# void decrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint8_t *decBuffer );
crypto.aes128_decrypt.argtypes = (ctypes.c_char_p, ctypes.c_uint16, ctypes.c_char_p, ctypes.c_char_p)

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