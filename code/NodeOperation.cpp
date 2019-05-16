#include "pch.h"

#include "NodeOperation.h"

void NodeOperation::setNodeLeft(Node *node) {

	if (node == NULL) {

		throw invalid_argument("noeud null");
	}

	_nodeLeft = node;
}

void NodeOperation::setNodeRight(Node *node) {

	if (node == NULL) {

		throw invalid_argument("noeud null");
	}

	_nodeRight = node;
}

NodeOperation::NodeOperation(Node *nodeLeft, Node *nodeRight) {

	setNodeLeft(nodeLeft);
	setNodeRight(nodeRight);
}

const Node *NodeOperation::getNodeLeft() const {

	return _nodeLeft;
}

const Node *NodeOperation::getNodeRight() const {

	return _nodeRight;
}

vector<Node*> NodeOperation::getDescendants() {

	vector<Node*> descendant;

	descendant.push_back(_nodeLeft);
	descendant.push_back(_nodeRight);

	return descendant;
}

void NodeOperation::search(string str) {

	_nodeLeft->search(str);
	_nodeRight->search(str);
}

NodeOperation::operator string() const {

	ostringstream os;

	os << "nodeLeft=" << (*getNodeLeft()) << ", nodeRight=" << (*getNodeRight());

	return os.str();
}