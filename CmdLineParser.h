#ifndef _CMDLINE_PARSER_H
#define _CMDLINE_PARSER_H

#include <string>
#include <vector>
#include <map>

enum e_arg_ids
{
	kNone = 0,
#ifdef CP_IGNORE_REST
	kIgnoreRest,
#endif	
	// i wish c++ had better enums...
#include "e_arg_ids.def"

};

class s_arg_param
{
private:
	std::string param;
public:
	s_arg_param(const std::string& param);

	std::string GetString();
	std::string GetStringOneOf(const std::vector<std::string>& options);
	double GetDouble();
	int GetInt();
	unsigned int GetUInt();
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

class CArgEntity
{
private:
	std::vector<s_arg_param> params;
	size_t cur_index;

public:
	e_arg_ids id;

	CArgEntity();
	CArgEntity(e_arg_ids id);
	void SetID(e_arg_ids id);
	void Add(s_arg_param& param);

	s_arg_param GetParam(size_t index);
	size_t size() const;
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
	CCommandLineParser(char** argv, int argc, s_arg_entry* arglist, size_t nargs);
	CArgEntity* GetCommand();
	CArgEntity* GetSwitch();
	bool GetSwitch(e_arg_ids id, CArgEntity** out);
	size_t NumberOfSwitches() const;

protected:
	virtual void RaiseError(const std::string& err);

private:
	char** argv;
	int argc, cur;
	const s_arg_entry* arglist;
	size_t nargs;

	CArgEntity command;
	std::map<e_arg_ids, CArgEntity> switches;
	std::map<e_arg_ids, CArgEntity>::iterator cur_switch;

	void ProcessCommand(const char* command_str);
	void ReadParams(const s_arg_entry* arg, CArgEntity& out);
	void ProcessSwitch(const char* switch_str);

#ifdef CP_LONG_SWITCH
	void ProcessSwitch(char c);
#endif

	bool ReadString(char** out);
	bool FindArgument(const char* arg, bool is_switch, const s_arg_entry** out) const;
};


#endif