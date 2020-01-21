#include<iostream>
#include <windows.h>
#include <vector>
#include "debugRegisters.h"
#include"keystone.h"
#include<Winternl.h>
#include<Psapi.h>
#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL
// 1. 包含BegEngine的头文件
//	Win32 是32位平台的程序可以使用的头文件
//	Win64 是64位平台的程序可以使用的头文件

#include "BeaEngine_4.1/Win32/headers/BeaEngine.h"
//2. 包含对应版本的静态库
#pragma comment (lib , "BeaEngine_4.1/Win32/Win32/Lib/BeaEngine.lib")
#pragma comment(linker, "/NODEFAULTLIB:\"crt.lib\"")
//#pragma comment(lib, "legacy_stdio_definitions.lib")
#pragma comment (lib , "keystone\\x86\\keystone_x86.lib")
#pragma comment (lib , "ntdll.lib")

using namespace std;

enum{
	cc,
	ram,
	hardware,
	condition,
	dr0,
	dr1,
	dr2,
	dr3
};
typedef struct{
	wchar_t name[MAX_PATH];
	LPVOID address;
}dlls;
typedef struct{
	DWORD type;			//种类
	LPVOID addr;		//断点地址
	DWORD   value;	//条件
	BYTE content;		//原来内容
}breakpoints;
		//进程加载时候设置
#pragma once

class extension
{
public:
	extension();
	~extension();
	virtual void output() = 0;
	virtual char* name() = 0;
};

class dbg
{
public:
	HANDLE hprocess;
	HANDLE htread;
	DEBUG_EVENT g_de = {};
	LPEXCEPTION_DEBUG_INFO pexcption = &g_de.u.Exception;
	vector<breakpoints> bps;
	breakpoints mmmm = {};
	LPVOID& addr;
	DWORD pid = 0;
	wchar_t szFile[260];
	DWORD exceptionHandle();
	DWORD resetAllpts();
	DWORD disableAllpts();
	BYTE setCC(LPVOID addr);
	DWORD printTxt(LPVOID address=0);
	void setTF();
	void decEip();
	void disableCC(breakpoints& bp);
	void listen();
	void run();
	void setOEP();
	bool isCall(DWORD &length);
	void stepOver();
	dbg();
 	~dbg();
private:
	int fujiaCC = 0;
	void findFile();
	int open = 0;
	int first = 1;
	int ttCC = 1;
	bool int3jmp;
	bool hdjmp;
	bool memjmp;
	bool processFile();
	DWORD stepOverContent;
	PROCESS_INFORMATION ps = {};
	bool bpExist(LPVOID addr);
	DWORD setBPHardRW(DWORD addr, DWORD type, DWORD len);
	DWORD setBPHardE(DWORD addr);
	bool regisertHardE(DWORD addr); 
	bool regisertHardRW(DWORD addr, DWORD type, DWORD len);
	void resetHD(bool b);
	void noTFreset();
	bool memBp(DWORD addr,DWORD type);
	void memReset(breakpoints& bp);
	void conditionBp(DWORD addr);
	breakpoints ifCondition();
	void showInfo();
	void readStack();
	void showData();
	void changeData(DWORD address);
	void writeCode(DWORD address);
	void readData(DWORD address);
	void printModules();
	void hidePEB();
	void hook();
	void extensions();
	void readExts();
	void dump(DWORD address);
	vector<extension*> exs;
	vector<dlls> dllary;
	typedef extension* (*outp)();
	void exportLs(LPVOID addr);
};

