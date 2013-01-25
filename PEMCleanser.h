#ifndef _PEMCLEANSER_H_
#define _PEMCLEANSER_H_

#include <cryptopp/filters.h>

// Ignores any data proceeding - until new line.
// ie will ignore lines such as -----BEGIN RSA PRIVATE KEY-----
class PEMCleanser : public CryptoPP::Bufferless<CryptoPP::Filter>
{
private:
	bool ignoreUntilNewLine;

public:
	PEMCleanser(BufferedTransformation *attachment=NULL)
		: ignoreUntilNewLine(false)
	{
		Detach(attachment);
	}

	size_t Put2(const byte *begin, size_t length, int messageEnd, bool blocking);
};

#endif