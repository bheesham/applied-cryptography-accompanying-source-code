#ifndef _IDEA_DEFINED

#define _IDEA_DEFINED

/* Defines for the PGP-style types used in IDEA.C */

#define word16	unsigned short int

/* IDEA algorithm constants */

#define IDEA_USERKEYSIZE	16
#define IDEA_BLOCKSIZE		8
#define IDEA_ROUNDS			8
#define IDEA_KEYLEN			( 6 * IDEA_ROUNDS + 4 )

/* Routines used to implement the IDEA encryption */

void ideaExpandKey( BYTE const *userkey, word16 *eKey, word16 *dKey );
void ideaCrypt( BYTE const *in, BYTE *out, word16 const *key );

#endif /* _IDEA_DEFINED */
