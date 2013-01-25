#define _CRT_SECURE_NO_DEPRECATE
#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <cryptopp/dll.h>
#include <boost/process.hpp>
#include <iostream>
#include "MyRSA.h"

using namespace CryptoPP;
using namespace std;

static const char* KEY_FILE_NAME = "7zCrypto_keyfile_u440eadIvX0oJk0G6KWw";

static OFB_Mode<AES>::Encryption s_globalRNG;
RandomNumberGenerator & GlobalRNG() { return s_globalRNG; }

// Throws std::exception
int Run7zip(std::vector<std::string>& args)
{
#ifdef _WIN32
	static const std::string exec = "7za.exe";
#else
	static const std::string exec = "7za";
#endif
	try {
		args.push_back("-y");
		boost::process::context ctx;
		ctx.work_dir = boost::filesystem::path(boost::filesystem::current_path()).generic_string();
		ctx.streams[boost::process::stdout_id] = boost::process::behavior::null();
		boost::process::child c = boost::process::create_child(exec, args, ctx);

		int exit_code = c.wait();
#if defined(BOOST_POSIX_API) 
		if (WIFEXITED(exit_code)) 
			exit_code = WEXITSTATUS(exit_code); 
#endif 
		return exit_code;
	} catch (boost::system::system_error& e) {
		throw std::runtime_error(e.what());
	}

}

// Invokes 7zip to test the input archive. 
// This is a pretty dirty/slow way of checking if the password was entered 
// correctly. However, it works with stock 7zip.
// On error a std::exception is thrown describing the error.
void Check7zPassword(const std::string& archivePath, const std::string& password)
{
	std::vector<std::string> args;
	args.push_back("t");
	args.push_back(archivePath);
	args.push_back("-p" + password);

	int exit_code = Run7zip(args);

	if (exit_code != EXIT_SUCCESS) {
		std::stringstream ss;
		ss << "7z failed with error code '" << exit_code << "'" << endl
			<< "   Wrong password?";
		throw std::runtime_error(ss.str().c_str());
	}

}

// Attempts to add a file to the specified archive.
// Throws std::exception on error.
void AddFileToArchive(const std::string& archive, const std::string& file)
{
	vector<string> args;
	args.push_back("a");
	args.push_back(archive);
	args.push_back(file);
	int exit_code = Run7zip(args);
	if (exit_code != EXIT_SUCCESS) {
		std::stringstream ss;
		ss << "Failed to add the key file to '" << archive << "'" << endl;
		throw std::runtime_error(ss.str().c_str());
	}
}

// puts it into the working dir
void ExtractKeyFileFromArchive(const std::string& archive)
{
	std::vector<std::string> args;
	args.push_back("x");
	args.push_back(archive);
	args.push_back(KEY_FILE_NAME);
	args.push_back("-p123"); // just so 7z will never ask for it.
	int exit_code = Run7zip(args);
	if (exit_code != EXIT_SUCCESS) {
		std::stringstream ss;
		ss << "Failed to extract '" << KEY_FILE_NAME << "' from '" << archive << "'" << endl;
		throw std::runtime_error(ss.str().c_str());
	}
}

void ExtractAllFilesFromArchive(const std::string& archive, 
	const std::string& password)
{
	std::vector<std::string> args;
	args.push_back("x");
	args.push_back(archive);
	args.push_back("-p" + password);
	int exit_code = Run7zip(args);
	if (exit_code != EXIT_SUCCESS) {
		std::stringstream ss;
		ss << "Failed to extract '" << archive << "'" << endl;
		throw std::runtime_error(ss.str().c_str());
	}
}

std::string ProcessKeyFile(const std::string& keysFile, RSA::PrivateKey& privateKey)
{
	fstream file(keysFile.c_str(), fstream::in);
	string line;
	while (getline(file, line)) {
		try	{
			return RSADecryptString(GlobalRNG(), privateKey, line.c_str());
		} catch(CryptoPP::Exception& e)	{
			cout << e.what() << endl;
		}
	}
	file.close();
	throw std::runtime_error("Password not found. Wrong private key??");
}

// Deletes the file when destroyed.
template <class T>
class CTempFile : public T
{
private:
	std::string file;
public:
	CTempFile(const char* file, std::ios_base::openmode mode) : 
	  T(file, mode), file(file) { }

	  ~CTempFile() {
		  boost::system::error_code ec;
		  boost::filesystem::remove(file, ec); // no throw
	  }
};


int main(int argc, char** argv)
{
	std::string command;
	if (argc > 1) command = argv[1];

	std::string seed = IntToString(time(NULL));
	seed.resize(16);
	s_globalRNG.SetKeyWithIV((byte *)seed.data(), 16, (byte *)seed.data());

	try {
		if (command == "a") { // build file and add to archive
			string archive, symmetric_key;
			
			cout << "7z archive : ";
			cin >> archive;

			vector<RSA::PublicKey> public_keys;
			cout << "Archive password : ";
			cin >> symmetric_key;

			cout << "\nChecking password..." << endl << endl;
			Check7zPassword(archive, symmetric_key);

			cout << "Enter the paths to public key files you wish to use. Send EOF when done." << endl;
			cin.ignore();
			while (1) {
				cout << "\nPublic key file : "; 
				string keyfile;
				if (!getline(cin, keyfile) || cin.bad()) break;
				
				try
				{
					RSA::PublicKey pubKey;
					if (!LoadKeyAndTryRaw<RSA::PublicKey>(GlobalRNG(), keyfile, pubKey)) {
						cout << "The key is corrupt!" << endl;
						continue;
					}
					
					public_keys.push_back(pubKey);
				}
				catch (FileStore::OpenErr&)
				{
					cout << "Unable to open the specified key file." << endl;
				}
				catch (BERDecodeErr&)
				{
					cout << "Cannot read the key. Are you sure it's public?" << endl;
				}
			}
			
			CTempFile<std::fstream> file(KEY_FILE_NAME, std::ios_base::out);
			
			// Build the key file
			for (size_t x = 0; x < public_keys.size(); x++) {
				string ciphertext = RSAEncryptString(GlobalRNG(), public_keys[x], 
						symmetric_key.c_str());
				file << ciphertext << endl;					
			}
			file.close(); // 7z will be wanting to read it
			AddFileToArchive(archive, KEY_FILE_NAME);
			
			cout << "\n\nThe key file was successfully added to '" << archive
				<< "'\nIt can now be decrypted with any matching private keys" << endl;
		} else if (command == "e") {
			string privateKey, archive;
			cout << "Archive : ";
			cin >> archive;
			cout << "Private key: ";
			cin >> privateKey;
			
			cout << "Loading key ... " << endl;
			RSA::PrivateKey privKey;

			if (!LoadKeyAndTryRaw<RSA::PrivateKey>(GlobalRNG(), privateKey, privKey)) {
				throw std::runtime_error("The key is corrupt!");
			}
			cout << "Loaded!" << endl;

			ExtractKeyFileFromArchive(archive);
			if (!boost::filesystem::exists(KEY_FILE_NAME)) 
				throw std::runtime_error("This archive doesn't have the required key file.");
			CTempFile<std::fstream> file(KEY_FILE_NAME, std::ios_base::in); // just so it deletes
			file.close();
			
			std::string password = ProcessKeyFile(KEY_FILE_NAME, privKey);
			ExtractAllFilesFromArchive(archive, password);
			cout << "\nThe archive was successfully extracted" << endl;
		} else if (command == "g") { // generate keys
			unsigned int keyLength;
			string publicKey, privateKey;
			cout << "Key length in bits : ";
			cin >> keyLength;
			cout << "Public key file : ";
			cin >> publicKey;
			cout << "Private key file : ";
			cin >> privateKey;

			GenerateRSAKey(GlobalRNG(), keyLength, privateKey.c_str(), 
				publicKey.c_str());
		} else {
			cout << "usage: " << endl;
			cout << "a - Generate and add key file to archive." << endl;
			cout << "e - Extract all files from the archive." << endl;
			cout << "g - Generate an RSA key pair." << endl << endl;
		}
	}
	catch(CryptoPP::Exception &e)
	{
		cout << "\nError : " << e.what() << endl;
		return -1;
	}
	catch (std::exception & e) 
	{
		cout << "\nError : " << e.what() << endl;
		return -1;
	}
	catch (...)
	{
		cout << "Unhandled exception" << endl;
	}

	return 0;
}