#include <stdlib.h>
#include <stdint.h>
#include "aes.h"
#include "cmac.h"
#include "utilities.h"
#include "crypto.h"

#ifdef DEBUG
#include <stdio.h>
#define DBGPRINT(format, ...) printf(format, __VA_ARGS__)
#else
#define DBGPRINT(format, ...) 
#endif


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
        memcpy1(inBlock, buffer + bufferIndex, size - bufferIndex);
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
        memcpy1(inBlock, buffer + bufferIndex, size - bufferIndex);
        aes_decrypt(inBlock, decBuffer + bufferIndex, &AesContext );
    }

#ifdef DEBUG
    DBGPRINT("OUT:");
    for(uint8_t i=0; i < orig_size; i++)
        DBGPRINT("%02x",decBuffer[i]);
    DBGPRINT("\n");
#endif
}