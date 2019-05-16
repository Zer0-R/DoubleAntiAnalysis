# Double Anti Analysis

## Utility: 
Workaround of anti-analytics techniques used by malware.

This tool detects anti-analsye techniques in malware. If a detected technique uses the cpuid instruction, the tool runs the malware with a patch that emulates a valid processor. This, so that the malware reveals its malicious actions to allow to analyze it.

The other anti-analysis techniques detected do not have a patch.

This tool is not associated with the DAA methodology but is an example of implementation.

## Requirement :
IDA Pro 5.0
Using the ```idag -B``` command for IDA to generate an .ASM. You can use another version by changing the name of this command in the Tool.cpp file.

DynamoRio
Using ```drcpusim```. The target malware is launched under a DynamoRIO client that monitors every instruction executed.


## Sample:
```
DoubleAntiAnalysis.exe sample.exe
```

![Result of sample execution on DAA](https://zupimages.net/up/19/20/9khc.jpg)
