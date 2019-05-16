#include "pch.h"

#ifndef DEF_PATCH_COMMAND
#define DEF_PATCH_COMMAND

#include <sstream>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

class PatchCommand {

	string _tool;
	string _command;

public:

	PatchCommand(string tool, string command);
	PatchCommand(PatchCommand &patchCommand);

	const string getTool() const;
	const string getCommand() const;
	
	void run(string path) const;

	operator string() const;
};

inline ostream &operator<<(ostream &os, const PatchCommand &patch_command) {

	os << (string)patch_command;

	return os;
}

#endif