#ifndef CRYPTOPP_RIPEMD_H
#define CRYPTOPP_RIPEMD_H

#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

class RIPEMD160 : public IteratedHash<word32>
{
public:
	RIPEMD160();
	void Final(byte *hash);
	unsigned int DigestSize() const {return DIGESTSIZE;}

	static void CorrectEndianess(word32 *out, const word32 *in, unsigned int byteCount)
	{
#ifndef IS_LITTLE_ENDIAN
		byteReverse(out, in, byteCount);
#else
		if (in!=out)
			memcpy(out, in, byteCount);
#endif
	}

	static void Transform(word32 *digest, const word32 *data);

	enum {DIGESTSIZE = 20, DATASIZE = 64};

private:
	void Init();
	void HashBlock(const word32 *input);
};

NAMESPACE_END

#endif
