#ifndef CRYPTOPP_CRC32_H
#define CRYPTOPP_CRC32_H

#include "cryptlib.h"

NAMESPACE_BEGIN(CryptoPP)

const word32 CRC32_NEGL = 0xffffffffL;

#ifdef IS_LITTLE_ENDIAN
#define CRC32_INDEX(c) (c & 0xff)
#define CRC32_SHIFTED(c) (c >> 8)
#else
#define CRC32_INDEX(c) (c >> 24)
#define CRC32_SHIFTED(c) (c << 8)
#endif

class CRC32 : public HashModule
{
public:
	CRC32();
	void Update(const byte *input, unsigned int length);
	void Final(byte *hash);
	unsigned int DigestSize() const {return 4;}

	void Reset() {m_crc = CRC32_NEGL;}
	void UpdateByte(byte b) {m_crc = m_tab[CRC32_INDEX(m_crc) ^ b] ^ CRC32_SHIFTED(m_crc);}
	byte GetCrcByte(unsigned int i) const {return ((byte *)&(m_crc))[i];}

private:
	static const word32 m_tab[256];
	word32 m_crc;
};

NAMESPACE_END

#endif
