#include "pch.h"

#include "Technical.h"

Technical::Technical(int id, string name, Node *node, PatchCommand *patch_command) : _id(id), _name(name), _patch_command(patch_command), _node(node) {}

Technical::Technical(int id, string name, Node *node) : Technical(id, name, node, NULL) {}

Technical::~Technical() {

	if (hasAPatch()) {
	
		delete _patch_command;
	}

	freeNode(_node);
}

const int Technical::getId() const {

	return _id;
}

const string Technical::getName() const {

	return _name;
}

PatchCommand *Technical::getPatchCommand() {

	return _patch_command;
}

Node *Technical::getNode() {

	return _node;
}

const bool Technical::hasAPatch() const {

	return _patch_command != NULL;
}

void Technical::freeNode(Node *node) {

	for (Node *n : node->getDescendants()) {

		freeNode(n);
	}

	delete node;
}

Technical::operator string() const {

	ostringstream os;

	os << "id=" << getId() << ", nom=" << getName() << ", node=" << (*_node);

	return os.str();
}