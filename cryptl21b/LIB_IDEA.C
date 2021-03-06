/****************************************************************************
*																			*
*						cryptlib IDEA Encryption Routines					*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#include "cryptctx.h"
#ifdef INC_ALL
  #include "idea.h"
#else
  #include "crypt/idea.h"
#endif /* Compiler-specific includes */

/* A structure to hold the two expanded IDEA keys */

typedef struct {
	WORD eKey[ IDEA_KEYLEN ];		/* The encryption key */
	WORD dKey[ IDEA_KEYLEN ];		/* The decryption key */
	} IDEA_KEY;

/* The size of the expanded IDEA keys */

#define IDEA_EXPANDED_KEYSIZE		sizeof( IDEA_KEY )

/****************************************************************************
*																			*
*								IDEA Self-test Routines						*
*																			*
****************************************************************************/

/* IDEA test vectors, from the ETH reference implementation */

/* The data structure for the ( key, plaintext, ciphertext ) triplets */

typedef struct {
	const BYTE key[ IDEA_USERKEYSIZE ];
	const BYTE plaintext[ IDEA_BLOCKSIZE ];
	const BYTE ciphertext[ IDEA_BLOCKSIZE ];
	} IDEA_TEST;

static const IDEA_TEST testIdea[] = {
	{ { 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
		0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08 },
	  { 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03 },
	  { 0x11, 0xFB, 0xED, 0x2B, 0x01, 0x98, 0x6D, 0xE5 } },
	{ { 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
		0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08 },
	  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
	  { 0x54, 0x0E, 0x5F, 0xEA, 0x18, 0xC2, 0xF8, 0xB1 } },
	{ { 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
		0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08 },
	  { 0x00, 0x19, 0x32, 0x4B, 0x64, 0x7D, 0x96, 0xAF },
	  { 0x9F, 0x0A, 0x0A, 0xB6, 0xE1, 0x0C, 0xED, 0x78 } },
	{ { 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
		0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08 },
	  { 0xF5, 0x20, 0x2D, 0x5B, 0x9C, 0x67, 0x1B, 0x08 },
	  { 0xCF, 0x18, 0xFD, 0x73, 0x55, 0xE2, 0xC5, 0xC5 } },
	{ { 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
		0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08 },
	  { 0xFA, 0xE6, 0xD2, 0xBE, 0xAA, 0x96, 0x82, 0x6E },
	  { 0x85, 0xDF, 0x52, 0x00, 0x56, 0x08, 0x19, 0x3D } },
	{ { 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
		0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08 },
	  { 0x0A, 0x14, 0x1E, 0x28, 0x32, 0x3C, 0x46, 0x50 },
	  { 0x2F, 0x7D, 0xE7, 0x50, 0x21, 0x2F, 0xB7, 0x34 } },
	{ { 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
		0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08 },
	  { 0x05, 0x0A, 0x0F, 0x14, 0x19, 0x1E, 0x23, 0x28 },
	  { 0x7B, 0x73, 0x14, 0x92, 0x5D, 0xE5, 0x9C, 0x09 } },
	{ { 0x00, 0x05, 0x00, 0x0A, 0x00, 0x0F, 0x00, 0x14,
		0x00, 0x19, 0x00, 0x1E, 0x00, 0x23, 0x00, 0x28 },
	  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
	  { 0x3E, 0xC0, 0x47, 0x80, 0xBE, 0xFF, 0x6E, 0x20 } },
	{ { 0x3A, 0x98, 0x4E, 0x20, 0x00, 0x19, 0x5D, 0xB3,
		0x2E, 0xE5, 0x01, 0xC8, 0xC4, 0x7C, 0xEA, 0x60 },
	  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
	  { 0x97, 0xBC, 0xD8, 0x20, 0x07, 0x80, 0xDA, 0x86 } },
	{ { 0x00, 0x64, 0x00, 0xC8, 0x01, 0x2C, 0x01, 0x90,
		0x01, 0xF4, 0x02, 0x58, 0x02, 0xBC, 0x03, 0x20 },
	  { 0x05, 0x32, 0x0A, 0x64, 0x14, 0xC8, 0x19, 0xFA },
	  { 0x65, 0xBE, 0x87, 0xE7, 0xA2, 0x53, 0x8A, 0xED } },
	{ { 0x9D, 0x40, 0x75, 0xC1, 0x03, 0xBC, 0x32, 0x2A,
		0xFB, 0x03, 0xE7, 0xBE, 0x6A, 0xB3, 0x00, 0x06 },
	  { 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08 },
	  { 0xF5, 0xDB, 0x1A, 0xC4, 0x5E, 0x5E, 0xF9, 0xF9 } }
	};

/* Test the IDEA code against the test vectors from the ETH reference
   implementation */

int ideaSelfTest( void )
	{
	BYTE temp[ IDEA_BLOCKSIZE ];
	WORD eKey[ IDEA_KEYLEN ], dKey[ IDEA_KEYLEN ];
	int i;

	for( i = 0; i < sizeof( testIdea ) / sizeof( IDEA_TEST ); i++ )
		{
		memcpy( temp, testIdea[ i ].plaintext, IDEA_BLOCKSIZE );
		ideaExpandKey( testIdea[ i ].key, eKey, dKey );
		ideaCrypt( temp, temp, eKey );
		if( memcmp( testIdea[ i ].ciphertext, temp, IDEA_BLOCKSIZE ) )
			return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform init and shutdown actions on an encryption context */

int ideaInit( CRYPT_INFO *cryptInfo, void *cryptInfoEx )
	{
	int status;

	UNUSED( cryptInfoEx );

	/* Allocate memory for the keyscheduled key */
	if( cryptInfo->ctxConv.key != NULL )
		return( CRYPT_INITED );
	if( ( status = krnlMemalloc( &cryptInfo->ctxConv.key, IDEA_EXPANDED_KEYSIZE ) ) != CRYPT_OK )
		return( status );
	cryptInfo->ctxConv.keyLength = IDEA_EXPANDED_KEYSIZE;

	return( CRYPT_OK );
	}

int ideaEnd( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxConv.key );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							IDEA En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int ideaEncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / IDEA_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		ideaCrypt( buffer, buffer, ideaKey->eKey );

		/* Move on to next block of data */
		buffer += IDEA_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int ideaDecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / IDEA_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		ideaCrypt( buffer, buffer, ideaKey->dKey );

		/* Move on to next block of data */
		buffer += IDEA_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int ideaEncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / IDEA_BLOCKSIZE;

	while( blockCount-- )
		{
		int i;

		/* XOR the buffer contents with the IV */
		for( i = 0; i < IDEA_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Encrypt a block of data */
		ideaCrypt( buffer, buffer, ideaKey->eKey );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->ctxConv.currentIV, buffer, IDEA_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += IDEA_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int ideaDecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->ctxConv.key;
	BYTE temp[ IDEA_BLOCKSIZE ];
	int blockCount = noBytes / IDEA_BLOCKSIZE;

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, IDEA_BLOCKSIZE );

		/* Decrypt a block of data */
		ideaCrypt( buffer, buffer, ideaKey->dKey );

		/* XOR the buffer contents with the IV */
		for( i = 0; i < IDEA_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->ctxConv.currentIV, temp, IDEA_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += IDEA_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	zeroise( temp, IDEA_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int ideaEncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->ctxConv.key;
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = IDEA_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Encrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i + ivCount ];
		memcpy( cryptInfo->ctxConv.currentIV + ivCount, buffer, bytesToUse );

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > IDEA_BLOCKSIZE ) ? IDEA_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		ideaCrypt( cryptInfo->ctxConv.currentIV,
				   cryptInfo->ctxConv.currentIV, ideaKey->eKey );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->ctxConv.currentIV, buffer, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % IDEA_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

int ideaDecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->ctxConv.key;
	BYTE temp[ IDEA_BLOCKSIZE ];
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = IDEA_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Decrypt the data */
		memcpy( temp, buffer, bytesToUse );
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i + ivCount ];
		memcpy( cryptInfo->ctxConv.currentIV + ivCount, temp, bytesToUse );

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > IDEA_BLOCKSIZE ) ? IDEA_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		ideaCrypt( cryptInfo->ctxConv.currentIV,
				   cryptInfo->ctxConv.currentIV, ideaKey->eKey );

		/* Save the ciphertext */
		memcpy( temp, buffer, ivCount );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->ctxConv.currentIV, temp, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % IDEA_BLOCKSIZE );

	/* Clear the temporary buffer */
	zeroise( temp, IDEA_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int ideaEncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->ctxConv.key;
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = IDEA_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Encrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i + ivCount ];

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > IDEA_BLOCKSIZE ) ? IDEA_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		ideaCrypt( cryptInfo->ctxConv.currentIV,
				   cryptInfo->ctxConv.currentIV, ideaKey->eKey );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % IDEA_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in OFB mode */

int ideaDecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->ctxConv.key;
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = IDEA_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Decrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i + ivCount ];

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > IDEA_BLOCKSIZE ) ? IDEA_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		ideaCrypt( cryptInfo->ctxConv.currentIV,
				   cryptInfo->ctxConv.currentIV, ideaKey->eKey );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % IDEA_BLOCKSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							IDEA Key Management Routines					*
*																			*
****************************************************************************/

/* Key schedule an IDEA key */

int ideaInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->ctxConv.key;

	/* Copy the key to internal storage */
	if( cryptInfo->ctxConv.userKey != key )
		memcpy( cryptInfo->ctxConv.userKey, key, keyLength );
	cryptInfo->ctxConv.userKeyLength = keyLength;

	/* Generate the expanded IDEA encryption and decrtption keys */
	ideaExpandKey( key, ideaKey->eKey, ideaKey->dKey );

	return( CRYPT_OK );
	}
