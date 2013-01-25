#include "MyRSA.h"
#include <cryptopp/hex.h>

using namespace CryptoPP;

template <>
void BERDecode<RSA::PrivateKey>(RSA::PrivateKey& key, BufferedTransformation& bt)
{
	key.BERDecodePrivateKey(bt, false, 0);
}
template <>
void BERDecode<RSA::PublicKey>(RSA::PublicKey& key, BufferedTransformation& bt)
{
	key.BERDecodePublicKey(bt, false, 0);
}

void GenerarePsuedoRandomString(RandomNumberGenerator& rng,
	char* out, size_t size_of_out)
{
	static const char* alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	static const int alphabet_len = strlen(alphabet);
	if (size_of_out <= 1) return;
	for (size_t x = 0; x < size_of_out-1; x++, out++)
		*out = alphabet[rng.GenerateByte() % alphabet_len];
	*out = '\0';
}

void GenerateRSAKey(RandomNumberGenerator& rng, 
	unsigned int keyLength, const char *privFilename, const char *pubFilename)
{
	char seed[33];
	GenerarePsuedoRandomString(rng, seed, sizeof(seed));
	RandomPool randPool;
	randPool.IncorporateEntropy((byte *)seed, strlen(seed));

	RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength);
	Base64Encoder privFile(new FileSink(privFilename));
	priv.DEREncode(privFile);
	privFile.MessageEnd();

	RSAES_OAEP_SHA_Encryptor pub(priv);
	Base64Encoder pubFile(new FileSink(pubFilename));
	pub.DEREncode(pubFile);
	pubFile.MessageEnd();
}

std::string RSAEncryptString(RandomNumberGenerator& rng,
	RSA::PublicKey& pubKey, const char *message)
{
	char seed[33];
	GenerarePsuedoRandomString(rng, seed, sizeof(seed));

	std::string result;
	RSAES_OAEP_SHA_Encryptor enc(pubKey);

	RandomPool randPool;
	randPool.IncorporateEntropy((byte *)seed, strlen(seed));

	StringSource(message, true, new PK_EncryptorFilter(randPool, enc, new HexEncoder(new StringSink(result))));
	return result;
}

std::string RSADecryptString(RandomNumberGenerator& rng, 
	RSA::PrivateKey& privKey, const char *ciphertext)
{
	RSAES_OAEP_SHA_Decryptor priv(privKey);

	std::string result;
	StringSource(ciphertext, true, new HexDecoder(new PK_DecryptorFilter(rng, priv, new StringSink(result))));
	return result;
}