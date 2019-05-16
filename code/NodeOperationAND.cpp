#include "pch.h"

#include "NodeOperationAND.h"

NodeOperationAND::NodeOperationAND(Node *nodeLeft, Node *nodeRight) : NodeOperation(nodeLeft, nodeRight) {}

const bool NodeOperationAND::isActivate() const {

	return getNodeLeft()->isActivate() && getNodeRight()->isActivate();
}