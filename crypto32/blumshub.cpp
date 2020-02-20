// blumshub.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "blumshub.h"

NAMESPACE_BEGIN(CryptoPP)

PublicBlumBlumShub::PublicBlumBlumShub(const Integer &n, const Integer &seed)
	: modn(n),
	  maxBits(BitPrecision(n.BitCount())-1)
{
	current = modn.Square(modn.Square(seed));
	bitsLeft = maxBits;
}

unsigned int PublicBlumBlumShub::GetBit()
{
	if (bitsLeft==0)
	{
		current = modn.Square(current);
		bitsLeft = maxBits;
	}

	return current.GetBit(--bitsLeft);
}

byte PublicBlumBlumShub::GetByte()
{
	byte b=0;
	for (int i=0; i<8; i++)
		b = (b << 1) | PublicBlumBlumShub::GetBit();
	return b;
}

BlumBlumShub::BlumBlumShub(const Integer &p, const Integer &q, const Integer &seed)
	: PublicBlumBlumShub(p*q, seed),
	  p(p), q(q),
	  x0(modn.Square(seed))
{
}

void BlumBlumShub::Seek(unsigned long index)
{
	Integer e = a_exp_b_mod_c (2, ((index*8) / maxBits + 1), (p-1)*(q-1));
	current = modn.Exponentiate(x0, e);
	bitsLeft = maxBits - int((index*8) % maxBits);
}

NAMESPACE_END
