#include "pch.h"

#include "File.h"

void File::setName(string name) {

	_name = name;
}

File::File(string path) : _path(path) {}

const string File::getName() const {

	return _name;
}

const string File::getPath() const {

	return _path;
}