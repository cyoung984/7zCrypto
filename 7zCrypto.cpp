#define _CRT_SECURE_NO_DEPRECATE
#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <cryptopp/dll.h>
#include <boost/process.hpp>
#include <iostream>
#include "MyRSA.h"
#include "CmdLineParser.h"
#include <memory>
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

// commands and switches need to be able to specify parameters
// params must directly follow the relevant command/switch
// there must only ever be one command
// 

/*class s_arg_param
{
private:
	std::string param;
public:
	s_arg_param(const std::string& param)
		: param(param) {}

	std::string GetString();
	std::string GetStringOneOf(const std::vector<std::string>& options);
	double GetDouble();
	int GetInt();
	unsigned int GetUInt();
};

enum e_arg_ids
{
	kNone = 0,
	kAddKeyToArchive,
	kExtractArchive,
	kGenerateKey,
	kSwitchPublicKey,
	kSwitchPrivateKey,
	kSwitchKeyLength,
	kSwitchArchive,
	kSwitchShow7zOutput,
	kSwitchForwardRestParams
};

struct s_arg_entry
{
	const char* str;
	e_arg_ids id;
	bool is_switch;
#ifdef CP_LONG_SWITCH
	bool long_switch;
#endif
	size_t nargs;
};

s_arg_entry g_arg_list[] = 
{
	{"a", kAddKeyToArchive, false, 0},
	{"e", kExtractArchive, false, 0},
	{"g", kGenerateKey, false, 0},
	{"pub", kSwitchPublicKey, true, 1},
	{"prv", kSwitchPrivateKey, true, 1},
	{"len", kSwitchKeyLength, true, 1},
	{"arc", kSwitchArchive, true, 1},
	{"v", kSwitchShow7zOutput, true},
	{"forward", kSwitchForwardRestParams, true, 0}
};
#define CP_IGNORE_REST	kSwitchForwardRestParams


class CArgEntity
{
private:
	std::vector<s_arg_param> params;
	size_t cur_index;
	
public:
	e_arg_ids id;

	CArgEntity() : id(kNone), cur_index(0) {}
	CArgEntity(e_arg_ids id) : id(id), cur_index(0) {}
	void SetID(e_arg_ids id) { this->id = id; }
	void Add(s_arg_param& param) { params.push_back(param); }
	const s_arg_param GetParam() { return params[cur_index++]; }
	size_t size() { return params.size(); }
};

class CCommandException : public std::exception
{
public:
	CCommandException(const char* err) : std::exception(err) {}
};

class CCommandLineParser
{
public:

	// first arg should be file path (ie exactly what comes from crt)
	CCommandLineParser(char** argv, int argc, s_arg_entry* arglist, size_t nargs)
		: argv(argv), argc(argc), cur(1), nargs(nargs), arglist(arglist)
	{
		char* command;
		while (ReadString(&command))
		{
			size_t size = strlen(command);
			if (size == 0) continue;
			if (size > 1 && command[0] == '-') { // switch
#ifdef CP_LONG_SWITCH
				bool long_switch = command[1] == '-';
				if (long_switch) ProcessSwitch(command + 2);
				else {
					for (size_t x = 1; x < size; x++)
						ProcessSwitch(command[x]);
				}
#else
				ProcessSwitch(command + 1);
#endif
			} else {
				ProcessCommand(command);
			}
		}

		cur_switch = switches.begin();
	}
	
	const CArgEntity& GetCommand() const { return command; }
	const CArgEntity GetSwitch() { return cur_switch++->second;	}
	bool GetSwitch(e_arg_ids id, CArgEntity& out) const {
		auto itr = switches.find(id);
		if (itr == switches.end()) return false;
		out = itr->second;
		return true;
	}

	size_t NumberOfSwitches() const { return switches.size(); }

	void ProcessCommand(const char* command_str)
	{
		const s_arg_entry* command;
		if (!FindArgument(command_str, false, &command))
			RaiseError("unknown command");

		if (this->command.id != kNone)
			RaiseError("unexpected command.. already got one.");
		this->command.SetID(command->id);
		ReadParams(command, this->command);		
	}

	void ReadParams(const s_arg_entry* arg, CArgEntity& out)
	{
		for (size_t x = 0; x < arg->nargs; x++) {
			char* arg_str;
			if (!ReadString(&arg_str)) RaiseError("expected arg");
			std::string str = arg_str;
			if (str.size() > 0){
				if (str.at(0) == '-') RaiseError("expected arg");
				out.Add(s_arg_param(arg_str));
			}
		}
	}

	void ProcessSwitch(const char* switch_str)
	{
		const s_arg_entry* s;
		if (!FindArgument(switch_str, true, &s))
			RaiseError("unknown switch");
		CArgEntity entity(s->id);
#ifdef CP_IGNORE_REST
		// special case: if we get the forward switch stop processing
		// everything and treat it as a single command.
		if (s->id == CP_IGNORE_REST) {
			char* arg_str;
			while (ReadString(&arg_str)) entity.Add(s_arg_param(arg_str));
		} else 	ReadParams(s, entity);
#else
		ReadParams(s, entity);
#endif
		switches.insert(std::pair<e_arg_ids, CArgEntity>(entity.id, entity));
	}

#ifdef CP_LONG_SWITCH
	void ProcessSwitch(char c)
	{
		char switch_str[2] = {c, 0};
		return ProcessSwitch(switch_str);
	}
#endif
		
protected:
	virtual void RaiseError(const std::string& err)
	{
		cout << "Throwing : " << err << endl;
		throw CCommandException(err.c_str());
	}
private:
	char** argv;
	int argc, cur;
	const s_arg_entry* arglist;
	size_t nargs;

	bool ReadString(char** out)
	{
		if (argc > cur) {
			*out = argv[cur++];
			return true;
		}
		else return false;
	}

	bool FindArgument(const char* arg, bool is_switch, const s_arg_entry** out) const
	{
		for (size_t i = 0; i < nargs; i++) {
			if (is_switch == arglist[i].is_switch &&
				!strcmp(arg, arglist[i].str)) {
				*out = &arglist[i];
				return true;
			}
		}
		return false;
	}
	
	CArgEntity command;
	std::map<e_arg_ids, CArgEntity> switches;
	std::map<e_arg_ids, CArgEntity>::iterator cur_switch;
//	size_t index;

};*/

s_arg_entry g_arg_list[] = 
{
	{"a", kAddKeyToArchive, false, 0},
	{"e", kExtractArchive, false, 0},
	{"g", kGenerateKey, false, 0},
	{"pub", kSwitchPublicKey, true, 1},
	{"prv", kSwitchPrivateKey, true, 1},
	{"len", kSwitchKeyLength, true, 1},
	{"arc", kSwitchArchive, true, 1},
	{"p", kSwitchArchivePassword, true, 1},
	{"v", kSwitchShow7zOutput, true},
	{"forward", kSwitchForwardRestParams, true, 0}
};
#define GET_NUMBER_ARGS(x) sizeof(x) / sizeof(s_arg_entry)

const char* usage_desc = "\n"
	"usage: <command> [<switches>...]\n\n"
	"<commands>:\n"
	"  a: Add keyfile to the archive\n"
	"  e: Extract files from the archive\n"
	"  g: Generate RSA key pair\n"
	"<switches>:\n"
	"  -pub <file>: the public key to use.\n"
	"  -prv <file>: the private key to use.\n"
	"  -len <positive integer>: the key length in bits\n"
	"  -arc <file>: the archive to operate on.\n"
	"  -p <password>: the archive's password\n"
	"  -v: verbose mode (show 7zip output)\n"
	"  -forward: forward all following command line data to 7zip.\n";

int show_help()
{
	cout << usage_desc << endl;
	return 1;
}

template <class T>
T ReadCommandLineType(s_arg_param p);
template <>
std::string ReadCommandLineType<std::string>(s_arg_param p)
{
	return p.GetString();
}
template <>
unsigned int ReadCommandLineType<unsigned int>(s_arg_param p)
{
	return p.GetUInt();
}

template <class T> 
T ReadFromUser(CCommandLineParser& c, e_arg_ids id, 
	const std::string& hint)
{
	T data;
	CArgEntity* arg;
	if (!c.GetSwitch(id, &arg)) {
		cout << hint << " : ";
		cin >> data;
	} else data = ReadCommandLineType<T>(arg->GetParam(0));
	return data;
}

std::string ReadArchiveName(CCommandLineParser& c)
{
	return ReadFromUser<std::string>(c, kSwitchArchive, "7z archive");
}

std::string ReadPrivateKeyFile(CCommandLineParser& c)
{
	return ReadFromUser<std::string>(c, kSwitchPrivateKey, "Private key file");
}

std::string ReadPublicKeyFile(CCommandLineParser& c)
{
	return ReadFromUser<std::string>(c, kSwitchPublicKey, "Public key file");
}

std::string ReadArchivePassword(CCommandLineParser& c)
{
	return ReadFromUser<std::string>(c, kSwitchArchivePassword, "Archive password");
}

unsigned int ReadKeyBitlength(CCommandLineParser& c)
{
	return ReadFromUser<unsigned int>(c, kSwitchKeyLength, "Key length in bits");
}

void ProcessPublicKeyFile(const std::string& keyfile, 
	std::vector<RSA::PublicKey>& public_keys)
{
	try
	{
		RSA::PublicKey pubKey;
		if (!LoadKeyAndTryRaw<RSA::PublicKey>(GlobalRNG(), keyfile, pubKey)) {
			cout << "The key is corrupt!" << endl;
			return;
		}
		public_keys.push_back(pubKey);
	}
	catch (const FileStore::OpenErr&)
	{
		cout << "Unable to open the specified key file.";
	}
	catch (const BERDecodeErr&)
	{
		cout << "Cannot read the key. Are you sure it's the public one?";
	}
	cout << endl;
}

int main(int argc, char** argv)
{
	try
	{
		CCommandLineParser c(argv, argc, g_arg_list, GET_NUMBER_ARGS(g_arg_list));

		const CArgEntity* command = c.GetCommand();
		if (command->id == kNone) return show_help();

		/*cout << c.NumberOfSwitches() << " switches." << endl;
		for (size_t x = 0; x < c.NumberOfSwitches(); x++) {
			const CArgEntity* s = c.GetSwitch();
			cout << "Switch with id " << s->id << endl;
		}*/

		std::string seed = IntToString(time(NULL));
		seed.resize(16);
		s_globalRNG.SetKeyWithIV((byte *)seed.data(), 16, (byte *)seed.data());

		switch (command->id)
		{
		case kAddKeyToArchive:
			{		
				std::string archive = ReadArchiveName(c);
				std::string symmetric_key = ReadArchivePassword(c);		
			
				cout << "\nChecking password..." << endl << endl;
				Check7zPassword(archive, symmetric_key);

				vector<RSA::PublicKey> public_keys;

				CArgEntity* arg;
				if (c.GetSwitch(kSwitchPublicKey, &arg)) 
					ProcessPublicKeyFile(arg->GetParam(0).GetString(), public_keys);
				else {
					cout << "Enter the paths to the public key files you wish to use. Send EOF when done.\n" << endl;
				
					while (1) {
						std::string keyfile;
						cout << "Public key file : ";
						cin >> keyfile;

						if (!keyfile.size()) break;
						ProcessPublicKeyFile(keyfile, public_keys);
					}
				}

				if (public_keys.size() == 0) 
					throw std::runtime_error("No keys were loaded.");

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
			} break;

		case kExtractArchive:
			{
				std::string archive = ReadArchiveName(c);
				std::string privateKey = ReadPrivateKeyFile(c);
				
				RSA::PrivateKey privKey;

				if (!LoadKeyAndTryRaw<RSA::PrivateKey>(GlobalRNG(), privateKey, privKey)) {
					throw std::runtime_error("The key is corrupt!");
				}
				
				ExtractKeyFileFromArchive(archive);
				if (!boost::filesystem::exists(KEY_FILE_NAME)) 
					throw std::runtime_error("This archive doesn't have the required key file.");
				CTempFile<std::fstream> file(KEY_FILE_NAME, std::ios_base::in); // just so it deletes
				file.close();

				std::string password = ProcessKeyFile(KEY_FILE_NAME, privKey);
				ExtractAllFilesFromArchive(archive, password);
				cout << "\nThe archive was successfully extracted" << endl;
			} break;

		case kGenerateKey:
			{
				unsigned int keyLength = ReadKeyBitlength(c);
				std::string publicKey = ReadPublicKeyFile(c);
				std::string privateKey = ReadPrivateKeyFile(c);
				
				GenerateRSAKey(GlobalRNG(), keyLength, privateKey.c_str(), 
					publicKey.c_str());
			} break;
		}
	}
	catch (const CCommandException& e)
	{
		cout << "invalid command line : " << e.what() << endl;
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
