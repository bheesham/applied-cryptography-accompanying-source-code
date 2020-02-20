/*
 * Author     :  Paul Kocher
 * E-mail     :  pck@netcom.com
 * Date       :  1997
 * Description:  C implementation of the Blowfish algorithm.
 */

#define MAXKEYBYTES 56          /* 448 bits */



typedef struct {

  unsigned long P[16 + 2];

  unsigned long S[4][256];

} BLOWFISH_CTX;



void Blowfish_Init(BLOWFISH_CTX *ctx, unsigned char *key, int keyLen);

void Blowfish_Encrypt(BLOWFISH_CTX *ctx, unsigned long *xl, unsigned long
*xr);

void Blowfish_Decrypt(BLOWFISH_CTX *ctx, unsigned long *xl, unsigned long
*xr);

int Blowfish_Test(BLOWFISH_CTX *ctx);       /* 0=ok, -1=bad */





