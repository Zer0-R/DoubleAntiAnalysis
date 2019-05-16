#include "pch.h"

#ifndef DEF_TECHNICAL
#define DEF_TECHNICAL

#include <sstream>
#include <iostream>
#include <string>
#include <vector>

#include "Node.h"
#include "PatchCommand.h"

using namespace std;

class Technical {

private:

	int _id;
	string _name;
	PatchCommand *_patch_command;
	Node *_node;

public:
	
	Technical(int id, string name, Node *node);
	Technical(int id, string name, Node *node, PatchCommand *patch_command);
	~Technical();

	const int getId() const;
	const string getName() const;
	PatchCommand *getPatchCommand();
	Node *getNode();

	const bool hasAPatch() const;

	void freeNode(Node *node);

	operator string() const;
};

inline ostream &operator<<(ostream &os, const Technical &technical) {

	os << (string)technical;

	return os;
}

#endif