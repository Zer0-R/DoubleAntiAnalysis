#include "pch.h"

#ifndef DEF_FILE
#define DEF_FILE

#include <string>

using namespace std;

class File {

private:

	string _name;
	string _path;

	void setName(string name);
public:

	File(string path);

	const string getName() const;
	const string getPath() const;
};

#endif