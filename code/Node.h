#include "pch.h"

#ifndef DEF_NODE
#define DEF_NODE

#include <sstream>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

class Node {

public:

	void virtual search(string str) = 0;
	const virtual bool isActivate() const = 0;
	vector<Node*> virtual getDescendants() = 0;

	operator string() const;
};

inline ostream &operator<<(ostream &os, const Node &node) {

	os << (string)node;

	return os;
}

#endif