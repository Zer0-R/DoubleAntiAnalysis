#include "pch.h"

#include "NodeSearch.h"

void NodeSearch::setIntensity(int intensity) {

	if (intensity < 0) {

		throw logic_error("intensite negative");
	}

	_intensity = intensity;
}

void NodeSearch::decreaseIntensity() {

	try {
		setIntensity(getIntensity() - 1);
	}
	catch (logic_error) {
	}
}

NodeSearch::NodeSearch(const string target, Node *node) : _target(target), _node(node), _intensity(0) {}

NodeSearch::NodeSearch(const string target) : NodeSearch(target, NULL) {}

const int NodeSearch::getIntensity() const {

	return _intensity;
}

const string NodeSearch::getTarget() const {

	return _target;
}
const Node *NodeSearch::getNode() const {

	return _node;
}

vector<Node*> NodeSearch::getDescendants() {

	vector<Node*> descendant;

	if (!isLeaf()) {

		descendant.push_back(_node);
	}

	return descendant;
}

void NodeSearch::search(string str) {

	if (!isLeaf() && getIntensity() > 0) {

		_node->search(str);
	}
	else if (str.find(getTarget()) != string::npos) {

		setIntensity(ACTIVATION_INTENSITY);
	}

	decreaseIntensity();
}

const bool NodeSearch::isActivate() const {

	if (isLeaf()) {

		return getIntensity() > 0;
	}

	return getNode()->isActivate();
}

const bool NodeSearch::isLeaf() const {

	return getNode() == NULL;
}

NodeSearch::operator string() const {

	ostringstream os;

	os << "target=" << getTarget() << ", intensity=" << getIntensity() << ", node=" << (*_node);

	return os.str();
}