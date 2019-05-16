#include "pch.h"

#include "PatchCommand.h"

PatchCommand::PatchCommand(string tool, string command) : _tool(tool), _command(command) {}

PatchCommand::PatchCommand(PatchCommand &patchCommand) {

	patchCommand._tool = this->_tool;
	patchCommand._command = this->_command;
}

const string PatchCommand::getTool() const {

	return _tool;
}

const string PatchCommand::getCommand() const {

	return _command;
}

void PatchCommand::run(string path) const {

	string command_patch;
	command_patch = getTool() + " " + getCommand() + " -- " + path;

	system(command_patch.c_str());
}

PatchCommand::operator string() const {

	ostringstream os;

	os << "PatchCommand[tool=" << getTool() << ", command=" << getCommand() << "]";

	return os.str();
}