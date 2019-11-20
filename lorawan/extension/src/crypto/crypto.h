#ifndef __LORAMAC_CRYPTO_H__
#define __LORAMAC_CRYPTO_H__


uint32_t aes_cmac( const uint8_t *buffer, uint16_t size, const uint8_t *key);
void aes128_encrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint8_t *encBuffer );
void aes128_decrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint8_t *decBuffer );


#endif // __LORAMAC_CRYPTO_H__
