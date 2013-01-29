#include "CmdLineParser.h"
#include <cstdlib>
#include <cstring>

// Helper function for StringToNumber
template <class T>
T _StringToNumber(const char* start, char** end);

template <>
int _StringToNumber<int>(const char* start, char** end) { return strtol(start, end, 10);	}
template <>
unsigned int _StringToNumber<unsigned int>(const char* start, char** end) { return strtoul(start, end, 10); }
template <>
double _StringToNumber<double>(const char* start, char** end) { return strtod(start, end);}

// Parse the input string as a number. If there are any characters that
// would produce a malformed number, false is returned.
template <class T>
bool StringToNumber(const std::string& str, T& out)
{
	const char* start = str.c_str(), *expected_end = start + str.size();
	char* end;
	T value = _StringToNumber<T>(start, &end);
	if (end != expected_end) return false;
	out = value;
	return true;
}

s_arg_param::s_arg_param(const std::string& param)	: param(param) 
{
}

s_arg_param::s_arg_param(const char* param) : param(param)
{
}

std::string s_arg_param::GetString()
{
	return param;
}

unsigned int s_arg_param::GetUInt()
{
	unsigned int n;
	if (!StringToNumber<unsigned int>(param, n))
		throw CCommandException("input not convertible to number");
	return n;
}

//-------------------------------------------------------------------------
CArgEntity::CArgEntity() : id(kNone), cur_index(0) 
{
}

CArgEntity::CArgEntity(e_arg_ids id) : id(id), cur_index(0) 
{
}

void CArgEntity::SetID(e_arg_ids id) 
{ 
	this->id = id;
}

void CArgEntity::Add(s_arg_param param) 
{ 
	params.push_back(param); 
}

s_arg_param CArgEntity::GetParam(size_t index) 
{ 
	return params[cur_index++];
}

size_t CArgEntity::size() const 
{ 
	return params.size();
}
//-------------------------------------------------------------------------

// first arg should be file path (ie exactly what comes from crt)
CCommandLineParser::CCommandLineParser(char** argv, int argc, 
	s_arg_entry* arglist, size_t nargs)
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

CArgEntity* CCommandLineParser::GetCommand() { return &command; }
CArgEntity* CCommandLineParser::GetSwitch() { return &cur_switch++->second;	}
bool CCommandLineParser::GetSwitch(e_arg_ids id, CArgEntity** out)
{
	switches_t::iterator itr = switches.find(id);
	if (itr == switches.end()) return false;
	*out = &itr->second;
	return true;
}

size_t CCommandLineParser::NumberOfSwitches() const 
{
	return switches.size(); 
}

void CCommandLineParser::ProcessCommand(const char* command_str)
{
	const s_arg_entry* command;
	if (!FindArgument(command_str, false, &command))
		RaiseError("unknown command");

	if (this->command.id != kNone)
		RaiseError("unexpected command.. already got one.");
	this->command.SetID(command->id);
	ReadParams(command, this->command);		
}

void CCommandLineParser::ReadParams(const s_arg_entry* arg, CArgEntity& out)
{
	for (size_t x = 0; x < arg->nargs; x++) {
		char* arg_str;
		if (!ReadString(&arg_str)) RaiseError("expected arg");
		std::string str = arg_str;
		if (str.size() > 0){
			if (str.at(0) == '-') RaiseError("expected arg");
			out.Add(arg_str);
		}
	}
}

void CCommandLineParser::ProcessSwitch(const char* switch_str)
{
	const s_arg_entry* s;
	if (!FindArgument(switch_str, true, &s))
		RaiseError("unknown switch");
	CArgEntity entity(s->id);
#ifdef CP_IGNORE_REST
	// special case: if we get the forward switch stop processing
	// everything and treat it as a single command.
	if (s->id == kIgnoreRest) {
		char* arg_str;
		while (ReadString(&arg_str)) entity.Add(arg_str);
	} else 	ReadParams(s, entity);
#else
	ReadParams(s, entity);
#endif
	switches.insert(std::pair<e_arg_ids, CArgEntity>(entity.id, entity));
}

#ifdef CP_LONG_SWITCH
void CCommandLineParser::ProcessSwitch(char c)
{
	char switch_str[2] = {c, 0};
	return ProcessSwitch(switch_str);
}
#endif

void CCommandLineParser::RaiseError(const std::string& err)
{
	throw CCommandException(err.c_str());
}

bool CCommandLineParser::ReadString(char** out)
{
	if (argc > cur) {
		*out = argv[cur++];
		return true;
	}
	else return false;
}

bool CCommandLineParser::FindArgument(const char* arg, bool is_switch, 
	const s_arg_entry** out) const
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
