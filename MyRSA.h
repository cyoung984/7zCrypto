#ifndef _MY_RSA_H_
#define _MY_RSA_H_

#include <string>
#include <cryptopp/rsa.h>
#include <cryptopp/randpool.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>

#include "PEMCleanser.h"

void GenerateRSAKey(CryptoPP::RandomNumberGenerator& rng,
	unsigned int keyLength, const char *privFilename, const char *pubFilename);
std::string RSAEncryptString(CryptoPP::RandomNumberGenerator& rng,
	CryptoPP::RSA::PublicKey& pubKey, const char *message);
std::string RSADecryptString(CryptoPP::RandomNumberGenerator& rng,
	CryptoPP::RSA::PrivateKey& privKey, const char *ciphertext);

template <class KeyType>
void BERDecode(KeyType& key, CryptoPP::BufferedTransformation& bt);

template <class KeyType>
bool LoadKey(CryptoPP::RandomNumberGenerator& rng, const std::string& file, 
	KeyType& key)
{
	using namespace CryptoPP;
	ByteQueue q;
	FileSource KeyFile(file.c_str(), true, new PEMCleanser(new Base64Decoder));
	KeyFile.TransferTo(q);
	key.Load(q);
	return key.Validate(rng, 2);	
}

// If key can't be loaded try treating it as raw (asn1 xxKey)
template <class KeyType>
bool LoadKeyAndTryRaw(CryptoPP::RandomNumberGenerator& rng, const std::string& file, 
	KeyType& key)
{
	using namespace CryptoPP;
	try { return LoadKey<KeyType>(rng, file, key); }
	catch (CryptoPP::Exception&)
	{
		ByteQueue q;
		FileSource KeyFile(file.c_str(), true, new PEMCleanser(new Base64Decoder));
		KeyFile.TransferTo(q);
		BERDecode<KeyType>(key, q);
	}
	return key.Validate(rng, 2);
}

#endif