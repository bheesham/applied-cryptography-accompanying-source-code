/****************************************************************************
*																			*
*					  cryptlib Blowfish Encryption Routines					*
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
  #include "blowfish.h"
#else
  #include "crypt/blowfish.h"
#endif /* Compiler-specific includes */

/* The size of the expanded Blowfish keys */

#define BLOWFISH_EXPANDED_KEYSIZE		sizeof( BF_KEY )

/****************************************************************************
*																			*
*							Blowfish Self-test Routines						*
*																			*
****************************************************************************/

/* Test the Blowfish code against Bruce Schneiers test vectors (1 & 2) and
   Mike Morgans test vector (3) */

int blowfishSelfTest( void )
	{
	BYTE *plain1 = ( BYTE * ) "BLOWFISH";
	BYTE *key1 = ( BYTE * ) "abcdefghijklmnopqrstuvwxyz";
	BYTE cipher1[] = { 0x32, 0x4E, 0xD0, 0xFE, 0xF4, 0x13, 0xA2, 0x03 };
	BYTE plain2[] = { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
	BYTE *key2 = ( BYTE * ) "Who is John Galt?";
	BYTE cipher2[] = { 0xCC, 0x91, 0x73, 0x2B, 0x80, 0x22, 0xF6, 0x84 };
	BYTE plain3[] = { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
	BYTE key3[] = { 0x41, 0x79, 0x6E, 0xA0, 0x52, 0x61, 0x6E, 0xE4 };
	BYTE cipher3[] = { 0xE1, 0x13, 0xF4, 0x10, 0x2C, 0xFC, 0xCE, 0x43 };
#if defined( __WIN32__ ) && defined( NT_DRIVER )	/* Kernel stack is tiny */
	static BF_KEY bfKey;
#else
	BF_KEY bfKey;
#endif /* __WIN32__ && NT_DRIVER */
	BYTE buffer[ 8 ];

	/* Test the Blowfish implementation */
	memcpy( buffer, plain1, 8 );
	BF_set_key( &bfKey, strlen( ( char * ) key1 ), key1 );
	BF_ecb_encrypt( buffer, buffer, &bfKey, BF_ENCRYPT );
	if( memcmp( buffer, cipher1, 8 ) )
		return( CRYPT_ERROR );
	BF_ecb_encrypt( buffer, buffer, &bfKey, BF_DECRYPT );
	if( memcmp( buffer, plain1, 8 ) )
		return( CRYPT_ERROR );
	memcpy( buffer, plain2, 8 );
	BF_set_key( &bfKey, strlen( ( char * ) key2 ), key2 );
	BF_ecb_encrypt( buffer, buffer, &bfKey, BF_ENCRYPT );
	if( memcmp( buffer, cipher2, 8 ) )
		return( CRYPT_ERROR );
	BF_ecb_encrypt( buffer, buffer, &bfKey, BF_DECRYPT );
	if( memcmp( buffer, plain2, 8 ) )
		return( CRYPT_ERROR );
	memcpy( buffer, plain3, 8 );
	BF_set_key( &bfKey, 8, key3 );
	BF_ecb_encrypt( buffer, buffer, &bfKey, BF_ENCRYPT );
	if( memcmp( buffer, cipher3, 8 ) )
		return( CRYPT_ERROR );
	BF_ecb_encrypt( buffer, buffer, &bfKey, BF_DECRYPT );
	if( memcmp( buffer, plain3, 8 ) )
		return( CRYPT_ERROR );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform init and shutdown actions on an encryption context */

int blowfishInit( CRYPT_INFO *cryptInfo )
	{
	int status;

	/* Allocate memory for the key and the algorithm-specific data within
	   the crypt context and set up any pointers we need */
	if( ( status = krnlMemalloc( &cryptInfo->ctxConv.key, BLOWFISH_EXPANDED_KEYSIZE ) ) != CRYPT_OK )
		return( status );
	cryptInfo->ctxConv.keyLength = BLOWFISH_EXPANDED_KEYSIZE;

	return( CRYPT_OK );
	}

int blowfishEnd( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxConv.key );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Blowfish En/Decryption Routines					*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int blowfishEncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BF_KEY *blowfishKey = ( BF_KEY * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / BF_BLOCK;

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		BF_ecb_encrypt( buffer, buffer, blowfishKey, BF_ENCRYPT );

		/* Move on to next block of data */
		buffer += BF_BLOCK;
		}

	return( CRYPT_OK );
	}

int blowfishDecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BF_KEY *blowfishKey = ( BF_KEY * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / BF_BLOCK;

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		BF_ecb_encrypt( buffer, buffer, blowfishKey, BF_DECRYPT );

		/* Move on to next block of data */
		buffer += BF_BLOCK;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int blowfishEncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
#if 0
	BF_KEY *blowfishKey = ( BF_KEY * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / BF_BLOCK;

	while( blockCount-- )
		{
		int i;

		/* XOR the buffer contents with the IV */
		for( i = 0; i < BF_BLOCK; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Encrypt a block of data */
		BF_ecb_encrypt( buffer, buffer, blowfishKey, BF_ENCRYPT );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->ctxConv.currentIV, buffer, BF_BLOCK );

		/* Move on to next block of data */
		buffer += BF_BLOCK;
		}
#endif
	BF_cbc_encrypt( buffer, buffer, noBytes, cryptInfo->ctxConv.key,
					cryptInfo->ctxConv.currentIV, BF_ENCRYPT );

	return( CRYPT_OK );
	}

int blowfishDecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
#if 0
	BF_KEY *blowfishKey = ( BF_KEY * ) cryptInfo->ctxConv.key;
	BYTE temp[ BF_BLOCK ];
	int blockCount = noBytes / BF_BLOCK;

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, BF_BLOCK );

		/* Decrypt a block of data */
		BF_ecb_encrypt( buffer, buffer, blowfishKey, BF_DECRYPT );

		/* XOR the buffer contents with the IV */
		for( i = 0; i < BF_BLOCK; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->ctxConv.currentIV, temp, BF_BLOCK );

		/* Move on to next block of data */
		buffer += BF_BLOCK;
		}

	/* Clear the temporary buffer */
	zeroise( temp, BF_BLOCK );
#endif
	BF_cbc_encrypt( buffer, buffer, noBytes, cryptInfo->ctxConv.key,
					cryptInfo->ctxConv.currentIV, BF_DECRYPT );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int blowfishEncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BF_KEY *blowfishKey = ( BF_KEY * ) cryptInfo->ctxConv.key;
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = BF_BLOCK - ivCount;
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
		ivCount = ( noBytes > BF_BLOCK ) ? BF_BLOCK : noBytes;

		/* Encrypt the IV */
		BF_ecb_encrypt( cryptInfo->ctxConv.currentIV,
						cryptInfo->ctxConv.currentIV, blowfishKey,
						BF_ENCRYPT );

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
	cryptInfo->ctxConv.ivCount = ( ivCount % BF_BLOCK );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

int blowfishDecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BF_KEY *blowfishKey = ( BF_KEY * ) cryptInfo->ctxConv.key;
	BYTE temp[ BF_BLOCK ];
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = BF_BLOCK - ivCount;
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
		ivCount = ( noBytes > BF_BLOCK ) ? BF_BLOCK : noBytes;

		/* Encrypt the IV */
		BF_ecb_encrypt( cryptInfo->ctxConv.currentIV,
						cryptInfo->ctxConv.currentIV, blowfishKey,
						BF_ENCRYPT );

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
	cryptInfo->ctxConv.ivCount = ( ivCount % BF_BLOCK );

	/* Clear the temporary buffer */
	zeroise( temp, BF_BLOCK );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int blowfishEncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BF_KEY *blowfishKey = ( BF_KEY * ) cryptInfo->ctxConv.key;
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = BF_BLOCK - ivCount;
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
		ivCount = ( noBytes > BF_BLOCK ) ? BF_BLOCK : noBytes;

		/* Encrypt the IV */
		BF_ecb_encrypt( cryptInfo->ctxConv.currentIV,
						cryptInfo->ctxConv.currentIV, blowfishKey,
						BF_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % BF_BLOCK );

	return( CRYPT_OK );
	}

/* Decrypt data in OFB mode */

int blowfishDecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BF_KEY *blowfishKey = ( BF_KEY * ) cryptInfo->ctxConv.key;
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = BF_BLOCK - ivCount;
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
		ivCount = ( noBytes > BF_BLOCK ) ? BF_BLOCK : noBytes;

		/* Encrypt the IV */
		BF_ecb_encrypt( cryptInfo->ctxConv.currentIV,
						cryptInfo->ctxConv.currentIV, blowfishKey,
						BF_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % BF_BLOCK );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Blowfish Key Management Routines				*
*																			*
****************************************************************************/

/* Get/set algorithm-specific parameters */

int blowfishGetKeysize( CRYPT_INFO *cryptInfo )
	{
	/* This is tricky, since we dynamically adjust the key type to 448 or
	   CRYPT_MAX_KEYSIZE bits depending on how much keying data we've been
	   passed by the user, but we can't tell in advance how much this will
	   be.  We get around this by taking advantage of the fact that when the
	   library queries the key size for an encryption context with no key
	   loaded, it always wants to know the maximum amount of data it can use
	   for a key, so we just return the maximum value */
	if( cryptInfo->ctxConv.userKeyLength == 0 )
		return( CRYPT_MAX_KEYSIZE );

	/* If the key has already been set up, just return the size of the key
	   we're using */
	return( cryptInfo->ctxConv.userKeyLength );
	}

/* Key schedule a Blowfish key */

int blowfishInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength )
	{
	/* Copy the key to internal storage */
	if( cryptInfo->ctxConv.userKey != key )
		memcpy( cryptInfo->ctxConv.userKey, key, keyLength );
	cryptInfo->ctxConv.userKeyLength = keyLength;

	BF_set_key( ( BF_KEY * ) cryptInfo->ctxConv.key, keyLength,
				( void * ) key );
	return( CRYPT_OK );
	}
