#include "pch.h"

#include "NodeOperationOR.h"

NodeOperationOR::NodeOperationOR(Node *nodeLeft, Node *nodeRight) : NodeOperation(nodeLeft, nodeRight) {}

const bool NodeOperationOR::isActivate() const {

	return getNodeLeft()->isActivate() || getNodeRight()->isActivate();
}