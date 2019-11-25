#include <stdlib.h>
#include <stdint.h>
#include "aes.h"
#include "cmac.h"
#include "utilities.h"
#include "crypto.h"

// #define DEBUG
#ifdef DEBUG
#include <stdio.h>
#define DBGPRINT(format, ...) printf(format, ## __VA_ARGS__)
#else
#define DBGPRINT(format, ...) 
#endif

/*!
 * CMAC/AES Message Integrity Code (MIC) Block B0 size
 */
 #define LORAMAC_MIC_BLOCK_B0_SIZE 16

/*!
 * MIC field computation initial data
 */
static uint8_t MicBlockB0[] = { 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


/*!
 * Contains the computed MIC field.
 *
 * \remark Only the 4 first bytes are used
 */
static uint8_t Mic[16];

/*!
 * Encryption aBlock and sBlock
 */
static uint8_t inBlock[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/*!
 * AES computation context variable
 */
static aes_context AesContext;

/*!
 * CMAC computation context variable
 */
static AES_CMAC_CTX AesCmacCtx[1];

uint32_t aes_cmac( const uint8_t *buffer, uint16_t size, const uint8_t *key)
{
    uint32_t mic = 0;

#ifdef DEBUG
    DBGPRINT("AES-CMAC: msg size:%d, key:", size);
    for(uint8_t i=0; i < 16; i++)
        DBGPRINT("%02x",key[i]);
#endif

#ifdef DEBUG
    DBGPRINT("\n msg:");
    for(uint8_t i=0; i < size; i++)
        DBGPRINT("%02x",buffer[i]);
    DBGPRINT("\n");
#endif

    AES_CMAC_Init( AesCmacCtx );
    AES_CMAC_SetKey( AesCmacCtx, key );
    AES_CMAC_Update( AesCmacCtx, buffer, size & 0xFF );
    AES_CMAC_Final( Mic, AesCmacCtx );


    mic = ( uint32_t )( ( uint32_t )Mic[3] << 24 | ( uint32_t )Mic[2] << 16 | ( uint32_t )Mic[1] << 8 | ( uint32_t )Mic[0] );
    DBGPRINT("MIC: %04x\n", mic);

    return mic;
}

void aes128_encrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint8_t *encBuffer )
{
    uint8_t bufferIndex = 0;
    uint16_t orig_size = size;

#ifdef DEBUG
    DBGPRINT("AES128 Encrypt: msg size:%d, key:", size);
    for(uint8_t i=0; i < 16; i++)
        DBGPRINT("%02x",key[i]);
    DBGPRINT("\n");

    DBGPRINT("IN:");
    for(uint8_t i=0; i < size; i++)
        DBGPRINT("%02x",buffer[i]);
    DBGPRINT("\n");
#endif

    memset1( AesContext.ksch, '\0', 240 );
    aes_set_key( key, 16, &AesContext );

    while( size >= 16 )
    {
        aes_encrypt( buffer + bufferIndex , encBuffer + bufferIndex, &AesContext );
        size -= 16;
        bufferIndex += 16;
    }

    if( size > 0 )
    {
        memset1(inBlock, 0, 16);
        memcpy1(inBlock, buffer + bufferIndex, size);
        aes_encrypt(inBlock, encBuffer + bufferIndex, &AesContext );
    }

#ifdef DEBUG
    DBGPRINT("OUT:");
    for(uint8_t i=0; i < orig_size; i++)
        DBGPRINT("%02x",encBuffer[i]);
    DBGPRINT("\n");
#endif
}

void aes128_decrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint8_t *decBuffer )
{
    uint8_t bufferIndex = 0;
    uint16_t orig_size = size;

#ifdef DEBUG
    DBGPRINT("AES128 Decrypt: msg size:%d, key:", size);
    for(uint8_t i=0; i < 16; i++)
        DBGPRINT("%02x",key[i]);
    DBGPRINT("\n");

    DBGPRINT("IN:");
    for(uint8_t i=0; i < size; i++)
        DBGPRINT("%02x",buffer[i]);
    DBGPRINT("\n");
#endif

    memset1( AesContext.ksch, '\0', 240 );
    aes_set_key( key, 16, &AesContext );

    while( size >= 16 )
    {
        aes_decrypt( buffer + bufferIndex , decBuffer + bufferIndex, &AesContext );
        size -= 16;
        bufferIndex += 16;
    }

    if( size > 0 )
    {
        memset1(inBlock, 0, 16);
        memcpy1(inBlock, buffer + bufferIndex, size);
        aes_decrypt(inBlock, decBuffer + bufferIndex, &AesContext );
    }

#ifdef DEBUG
    DBGPRINT("OUT:");
    for(uint8_t i=0; i < orig_size; i++)
        DBGPRINT("%02x",decBuffer[i]);
    DBGPRINT("\n");
#endif
}

void compute_session_key(const uint8_t *key,  uint32_t appnonce, uint32_t netid, uint16_t devnonce, uint8_t keytype, uint8_t *skey)
{
    uint8_t nonce[16];
    memset1( nonce, 0, sizeof( nonce ) );

    nonce[0] =  keytype;
    nonce[1] = appnonce & 0xff;
    nonce[2] = (appnonce >> 8) & 0xff;
    nonce[3] = (appnonce >> 16) & 0xff;
    nonce[4] = netid & 0xff;
    nonce[5] = (netid >> 8) & 0xff;
    nonce[6] = (netid >> 16) & 0xff;
    nonce[7] = devnonce & 0xff;
    nonce[8] = (devnonce >> 8) & 0xff;

    memset1( AesContext.ksch, '\0', 240 );
    aes_set_key( key, 16, &AesContext );
    aes_encrypt( nonce, skey, &AesContext );

#ifdef DEBUG
    DBGPRINT("KEY:");
    for(uint8_t i=0; i < 16; i++)
        DBGPRINT("%02x",key[i]);
    DBGPRINT("\n");

    DBGPRINT("Nonce:");
    for(uint8_t i=0; i < 16; i++)
        DBGPRINT("%02x",nonce[i]);
    DBGPRINT("\n");

    DBGPRINT("SKey:");
    for(uint8_t i=0; i < 16; i++)
        DBGPRINT("%02x",skey[i]);
    DBGPRINT("\n");
#endif
}

void compute_app_skey(const uint8_t *key,  uint32_t appnonce, uint32_t netid, uint16_t devnonce, uint8_t *nwkSKey)
{
  DBGPRINT("compute_app_skey:\r\n");
  compute_session_key(key,  appnonce, netid, devnonce, 2, nwkSKey);
}

void compute_nwk_skey(const uint8_t *key,  uint32_t appnonce, uint32_t netid, uint16_t devnonce, uint8_t *nwkSKey)
{
  DBGPRINT("compute_nwk_skey:\r\n");
  compute_session_key(key,  appnonce, netid, devnonce, 1, nwkSKey);
}

uint32_t compute_mic(const uint8_t *buffer, uint16_t size, const uint8_t *key, uint32_t devaddr, uint8_t dir, uint32_t fcnt)
{
    MicBlockB0[5] = dir;
    
    MicBlockB0[6] = ( devaddr ) & 0xFF;
    MicBlockB0[7] = ( devaddr >> 8 ) & 0xFF;
    MicBlockB0[8] = ( devaddr >> 16 ) & 0xFF;
    MicBlockB0[9] = ( devaddr >> 24 ) & 0xFF;

    MicBlockB0[10] = ( fcnt ) & 0xFF;
    MicBlockB0[11] = ( fcnt >> 8 ) & 0xFF;
    MicBlockB0[12] = ( fcnt >> 16 ) & 0xFF;
    MicBlockB0[13] = ( fcnt >> 24 ) & 0xFF;

    MicBlockB0[15] = size & 0xFF;

    AES_CMAC_Init( AesCmacCtx );

    AES_CMAC_SetKey( AesCmacCtx, key );

    AES_CMAC_Update( AesCmacCtx, MicBlockB0, LORAMAC_MIC_BLOCK_B0_SIZE );
    
    AES_CMAC_Update( AesCmacCtx, buffer, size & 0xFF );
    
    AES_CMAC_Final( Mic, AesCmacCtx );

#ifdef DEBUG
    DBGPRINT("KEY:");
    for(uint8_t i=0; i < 16; i++)
        DBGPRINT("%02x",key[i]);
    DBGPRINT("\n");

    DBGPRINT("B0:");
    for(uint8_t i=0; i < 16; i++)
        DBGPRINT("%02x",MicBlockB0[i]);
    DBGPRINT("\n");

    DBGPRINT("buffer(sz=%d):", size);
    for(uint8_t i=0; i < size; i++)
        DBGPRINT("%02x",buffer[i]);
    DBGPRINT("\n");
#endif

   uint32_t mic = ( uint32_t )( ( uint32_t )Mic[3] << 24 | ( uint32_t )Mic[2] << 16 | ( uint32_t )Mic[1] << 8 | ( uint32_t )Mic[0] );
   DBGPRINT("MIC=%04x",mic);
   return mic;
}

uint32_t compute_uplink_mic(const uint8_t *buffer, uint16_t size, const uint8_t *key, uint32_t devaddr,  uint32_t fcnt)
{
    #define UP_DIR 0
    return compute_mic(buffer, size, key, devaddr, UP_DIR,  fcnt);
}
