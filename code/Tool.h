#include "pch.h"

#ifndef DEF_TOOL
#define DEF_TOOL

#include <fstream>
#include <sstream>
#include <iostream>
#include <string>
#include <vector>
#include <iterator>
#include <map>

#include "NodeSearch.h"
#include "NodeOperationAND.h"
#include "NodeOperationOR.h"
#include "Technical.h"

using namespace std;

class Tool {

public:

	static vector<string> explode(string const &s, char delim);

	static void buildAssembler(string path);

	static bool isInstruction(string line);

	static bool isAnAsmFile(string file);

	static int getMaxSizeNames(vector<Technical*> technicals);

	static void deleteExtension(string &file);

	static vector<Technical*> getTecnicals();
};

#endif