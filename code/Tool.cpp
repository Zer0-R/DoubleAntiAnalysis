#include "pch.h"

#include "Tool.h"

vector<string> Tool::explode(string const &s, char delim) {

	vector<std::string> result;
	istringstream iss(s);

	for (string token; getline(iss, token, delim); ) {

		result.push_back(std::move(token));
	}

	return result;
}

void Tool::buildAssembler(string path) {

	string command = "idag -B \"" + path + "\"";

	system(command.c_str());
}

bool Tool::isInstruction(string line) {

	return (int)line[0] == 9 && (int)line[1] == 9 && (int)line[2] != 9 && line[2] != ';';
}

bool Tool::isAnAsmFile(string file) {

	return file.find(".asm") != string::npos;
}

int Tool::getMaxSizeNames(vector<Technical*> technicals) {

	int size, max = 0;

	for (Technical *technical : technicals) {

		size = technical->getName().size();

		if (size > max) {

			max = size;
		}
	}

	return max;
}

void Tool::deleteExtension(string &file) {

	if (file[file.length() - 4] == '.') {

		file = file.substr(0, file.length() - 4);
	}
}

vector<Technical*> Tool::getTecnicals() {

	vector<Technical*> technicals;
	int id = 0;
	Node *node;

	// technique 1
	node = new NodeSearch("		call	ds:GetTickCount");
	node = new NodeSearch("		call	ds:GetTickCount", node);
	technicals.push_back(new Technical(id++, "if time has been accelerated", node));

	// technique 2
	node = new NodeSearch("		call	ds:DeviceIoControl");
	technicals.push_back(new Technical(id++, "hard disk size using DeviceControl", node));

	// technique 3
	node = new NodeSearch("		call	ds:SetupDiGetClassDevsEx");
	technicals.push_back(new Technical(id++, "SetupDi_diskdrive", node));

	// technique 4
	node = new NodeSearch("		call	ds:GetCursorPos");
	node = new NodeSearch("		call	ds:GetCursorPos", node);
	technicals.push_back(new Technical(id++, "mouse movement", node));

	// technique 5
	node = new NodeSearch("		call	ds:GlobalMemoryStatusEx");
	technicals.push_back(new Technical(id++, "memory space using GlobalMemoryStatusEx", node));

	// technique 6
	node = new NodeSearch("		call	ds:GetDiskFreeSpaceExW");
	technicals.push_back(new Technical(id++, "disk size using GetDiskFreeSpaceEx", node));

	// technique 7
	node = new NodeSearch("40h");
	node = new NodeSearch("		str", node);
	technicals.push_back(new Technical(id++, "Store Task Register", node));

	// technique 8
	node = new NodeSearch("		call	ds:EnumServicesStatusExW");
	technicals.push_back(new Technical(id++, "VM Driver Services", node));

	// technique 9
	node = new NodeSearch("		call	j_GetPwrCapabilities");
	technicals.push_back(new Technical(id++, "power capabilities", node));

	// technique 10
	node = new NodeSearch("		call	ds:GetSystemFirmwareTable");
	technicals.push_back(new Technical(id++, "firmware SMBIOS or ACPI", node));

	// technique 11
	node = new NodeSearch("		call	ds:RegOpenKeyExW");
	technicals.push_back(new Technical(id++, "registry", node));

	// technique 12
	node = new NodeSearch("		call	ds:dwNumberOfProcessors");
	technicals.push_back(new Technical(id++, "number of processor in machine", node));

	// technique 13
	node = new NodeSearch("		sldt");
	technicals.push_back(new Technical(id++, "local descriptor table location", node));

	// technique 14
	node = new NodeSearch("		lidt");
	technicals.push_back(new Technical(id++, "interrupt descriptor table location", node));

	// technique 15
	node = new NodeSearch("		mov ss, ax");
	node = new NodeSearch("		lgdt", node);
	technicals.push_back(new Technical(id++, "global descriptor table location", node));

	//// CPUID ////

	// technique 16
	node = new NodeSearch("1Fh");
	node = new NodeSearch("		cpuid", node);
	technicals.push_back(new Technical(id++, "if CPU hypervisor field is set using cpuid(0x1)", node, 
		new PatchCommand("drrun", "-t drcpusim -continue -cpu Core2")));

	// technique 17
	node = new NodeSearch("40000000");
	node = new NodeSearch("		cpuid", node);
	technicals.push_back(new Technical(id++, "if hypervisor vendor using cpuid(0x40000000)", node, 
		new PatchCommand("drrun", "-t drcpusim -continue -cpu Core2")));

	//// USING VMI ////

	// technique 18
	node = new NodeSearch("Win32_BIOS");
	technicals.push_back(new Technical(id++, "SerialNumber from BIOS using WMI", node));

	// technique 19
	node = new NodeSearch("Model");
	node = new NodeSearch("Win32_ComputerSystem", node);
	technicals.push_back(new Technical(id++, "Model from ComputerSystem using WMI", node));

	// technique 20
	node = new NodeSearch("Manufacturer");
	node = new NodeSearch("Win32_ComputerSystem", node);
	technicals.push_back(new Technical(id++, "Manufacturer from ComputerSystem using WMI", node));

	// technique 21
	node = new NodeSearch("CurrentTemperature");
	node = new NodeSearch("MSAcpi_ThermalZoneTemperature", node);
	technicals.push_back(new Technical(id++, "current Temperature using WMI", node));

	// technique 22
	node = new NodeSearch("ProcessorId");
	node = new NodeSearch("Win32_Processor", node);
	technicals.push_back(new Technical(id++, "ProcessId using WMI", node));

	// technique 23
	node = new NodeSearch("Win32_Fan");
	technicals.push_back(new Technical(id++, "CPU fan using WMI", node));

	// technique 24
	node = new NodeSearch("MACAddress");
	node = new NodeSearch("Win32_NetworkAdapterConfiguration", node);
	technicals.push_back(new Technical(id++, "mac address using WMI", node));

	// technique 25
	node = new NodeSearch("FileName");
	node = new NodeSearch("Win32_NTEventlogFile", node);
	technicals.push_back(new Technical(id++, "event log using WMI", node));

	// technique 26
	node = new NodeSearch("Win32_Processor");
	technicals.push_back(new Technical(id++, "number of cores in machine using WMI", node));

	// technique 27
	node = new NodeSearch("Win32_LogicalDisk");
	technicals.push_back(new Technical(id++, "hard disk size using WMI", node));

	//// TIMING ATTACK ////

	// technique 28
	node = new NodeSearch("		rdtsc", new NodeSearch("		rdtsc"));
	node = new NodeOperationOR(node, new NodeSearch("		call	ds:SetTimer"));
	node = new NodeOperationOR(node, new NodeSearch("ds:Sleep"));
	node = new NodeOperationOR(node, new NodeSearch("		call	ds:CreateWaitableTimerW"));
	node = new NodeOperationOR(node, new NodeSearch("		call	ds:CreateTimerQueueTimer"));

	technicals.push_back(new Technical(id++, "sandboxed used timeout", node));

	// technique 29
	node = new NodeOperationOR(new NodeSearch("ollydbg.exe"), new NodeSearch("ProcessHacker.exe"));
	node = new NodeOperationOR(node, new NodeSearch("tcpview.exe"));
	node = new NodeOperationOR(node, new NodeSearch("autoruns.exe"));
	node = new NodeOperationOR(node, new NodeSearch("autorunsc.exe"));
	node = new NodeOperationOR(node, new NodeSearch("filemon.exe"));
	node = new NodeOperationOR(node, new NodeSearch("procmon.exe"));
	node = new NodeOperationOR(node, new NodeSearch("regmon.exe"));
	node = new NodeOperationOR(node, new NodeSearch("procexp.exe"));
	node = new NodeOperationOR(node, new NodeSearch("idaq.exe"));
	node = new NodeOperationOR(node, new NodeSearch("idaq64.exe"));
	node = new NodeOperationOR(node, new NodeSearch("ImmunityDebugger.exe"));
	node = new NodeOperationOR(node, new NodeSearch("Wireshark.exe"));
	node = new NodeOperationOR(node, new NodeSearch("dumpcap.exe"));
	node = new NodeOperationOR(node, new NodeSearch("HookExplorer.exe"));
	node = new NodeOperationOR(node, new NodeSearch("ImportREC.exe"));
	node = new NodeOperationOR(node, new NodeSearch("LordPE.exe"));
	node = new NodeOperationOR(node, new NodeSearch("SysInspector.exe"));
	node = new NodeOperationOR(node, new NodeSearch("proc_analyzer.exe"));
	node = new NodeOperationOR(node, new NodeSearch("sysAnalyzer.exe"));
	node = new NodeOperationOR(node, new NodeSearch("sniff_hit.exe"));
	node = new NodeOperationOR(node, new NodeSearch("windbg.exe"));
	node = new NodeOperationOR(node, new NodeSearch("joeboxcontrol.exe"));
	node = new NodeOperationOR(node, new NodeSearch("joeboxserver.exe"));
	technicals.push_back(new Technical(id++, "blacklisted files", node));

	node = new NodeOperationOR(new NodeSearch("sbiedll.dll"), new NodeSearch("dbghelp.dll"));
	node = new NodeOperationOR(node, new NodeSearch("api_log.dll"));
	node = new NodeOperationOR(node, new NodeSearch("dir_watch.dll"));
	node = new NodeOperationOR(node, new NodeSearch("pstorec.dll"));
	node = new NodeOperationOR(node, new NodeSearch("vmcheck.dll"));
	node = new NodeOperationOR(node, new NodeSearch("wpespy.dll"));
	node = new NodeOperationOR(node, new NodeSearch("avghookx.dll"));
	node = new NodeOperationOR(node, new NodeSearch("avghooka.dll"));
	node = new NodeOperationOR(node, new NodeSearch("snxhk.dll"));
	technicals.push_back(new Technical(id++, "the current processes", node));

	return technicals;
}
