#include "pch.h"

#ifndef DEF_NODE_OPERATION
#define DEF_NODE_OPERATION

#include "Node.h"

using namespace std;

class NodeOperation : public Node {

private:

	Node *_nodeLeft;
	Node *_nodeRight;

	void setNodeLeft(Node *node);
	void setNodeRight(Node *node);

public:

	NodeOperation(Node *nodeLeft, Node *nodeRight);

	const Node *getNodeLeft() const;
	const Node *getNodeRight() const;

	vector<Node*> getDescendants();
	void search(string str);

	operator string() const;
};

inline ostream &operator<<(ostream &os, const NodeOperation &nodeOperation) {

	os << (string)nodeOperation;

	return os;
}

#endif