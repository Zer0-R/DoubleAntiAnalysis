#include "pch.h"

#ifndef DEF_NODE_OPERATION_AND
#define DEF_NODE_OPERATION_AND

#include "NodeOperation.h"

using namespace std;

class NodeOperationAND : public NodeOperation {

public:

	NodeOperationAND(Node *nodeLeft, Node *nodeRight);

	const bool isActivate() const;
};

#endif