#include "pch.h"

#include "Node.h"

Node::operator string() const {

	ostringstream os;

	os << "activate=" << isActivate();

	return os.str();
}