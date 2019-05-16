#include "pch.h"

#ifndef DEF_NODE_OPERATION_OR
#define DEF_NODE_OPERATION_OR

#include "NodeOperation.h"

using namespace std;

class NodeOperationOR : public NodeOperation {

public:

	NodeOperationOR(Node *nodeLeft, Node *nodeRight);

	const bool isActivate() const;
};

#endif