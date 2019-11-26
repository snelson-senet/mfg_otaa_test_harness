#ifndef __LORAMAC_CRYPTO_H__
#define __LORAMAC_CRYPTO_H__


uint32_t aes_cmac( const uint8_t *buffer, uint16_t size, const uint8_t *key);
void aes128_encrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint8_t *encBuffer );
void aes128_decrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint8_t *decBuffer );
void compute_app_skey(const uint8_t *key,  uint32_t appnonce, uint32_t netid, uint16_t devnonce, uint8_t *nwkSKey);
void compute_nwk_skey(const uint8_t *key,  uint32_t appnonce, uint32_t netid, uint16_t devnonce, uint8_t *nwkSKey);
uint32_t compute_uplink_mic(const uint8_t *buffer, uint16_t size, const uint8_t *key, uint32_t devaddr,  uint32_t fcnt);


#endif // __LORAMAC_CRYPTO_H__
