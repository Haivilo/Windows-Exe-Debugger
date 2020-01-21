//#include<iostream>
//#include <windows.h>
//#include <vector>
//#include "debugRegisters.h"
//#define BEA_ENGINE_STATIC
//#define BEA_USE_STDCALL
//#include "Win32/headers/BeaEngine.h"
//#pragma comment(lib, "BeaEngine.lib")
//#pragma comment(linker, "/NODEFAULTLIB:\"crt.lib\"")
//#pragma comment(lib, "legacy_stdio_definitions.lib")
//
//using namespace std;
//wchar_t szFile[260];
//DEBUG_EVENT g_de = {};
//LPEXCEPTION_DEBUG_INFO pexcption = &g_de.u.Exception;
//breakpoints bp;
//vector<breakpoints> bps;
//LPVOID addr = nullptr;	
//DWORD pid = 0;			//进程加载时候设置
//enum{
//	cc,
//	ram,
//	hardware
//};
//typedef struct{
//	DWORD type;			//种类
//	LPVOID addr;		//断点地址
//	BOOL   isEnable;	//是否启用断点
//	BYTE content;		//原来内容
//}breakpoints;
//
////用来打开文件，szFile保存
//void findFile()
//{
//	OPENFILENAME ofn;
//	
//	ZeroMemory(&ofn, sizeof(ofn));
//	ofn.lStructSize = sizeof(ofn);
//	ofn.lpstrFile =szFile;
//	ofn.lpstrFile[0] = '\0';
//	ofn.nMaxFile = sizeof(szFile);
//	ofn.lpstrFilter = L"All\0*.*\0Text\0*.TXT\0";
//	ofn.nFilterIndex = 1;
//	ofn.lpstrFileTitle = NULL;
//	ofn.nMaxFileTitle = 0;
//	ofn.lpstrInitialDir = NULL;
//	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
//	GetOpenFileName(&ofn);
////	strcpy_s(ret, strlen(ofn.lpstrFile) + 1, ofn.lpstrFile);
//}
//
//DWORD ShowAsm(LPVOID addr, DWORD dwPid)
//{
//	char buff[1024] = {};
//	DWORD dwRead = 0;
//	//1. 打开进程
//	HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_de.dwProcessId);
//
//	//2.读取内存
//	ReadProcessMemory(hprocess, addr, buff, 1024, &dwRead);
//	//3.反汇编
//
//	DISASM disasm = {};
//	disasm.Archi = 0;			//x86汇编
//	disasm.EIP = (UIntPtr)buff;			//缓冲区
//	disasm.VirtualAddr = (UInt64)addr;	//显示地址
//	DWORD contlen = 0;
//	contlen = Disasm(&disasm);
//	printf("%08X %s\n", addr, disasm.CompleteInstr);
//	//4.关闭进程
//	CloseHandle(hprocess);
//	return contlen;
//}
////用来下CC断点
//bool SetCCBreakPoint(LPVOID addr){
//	//是否重复下断点
//	for (auto i : bps)
//	{
//		if (addr == i.addr)
//			return false;
//	}
//	//保存软件断点
//	//BREAKPOINT_INFO bp = {};
//	//bp.addr = addr;
//	//bp.isEnbale = TRUE;
//	DWORD dwRead;
//	DWORD protect;
//	char cc = 0xcc;
//	breakpoints bp;
//	bp.isEnable = 1;
//	bp.addr = addr;
//	bp.type = cc;
//	//1.打开进程句柄
//	DWORD oldProtect = 0;
//	HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_de.dwProcessId);
//	//2.修改内存属性
//	VirtualProtectEx(hprocess, addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
//	//3.读取原始数据
//	ReadProcessMemory(hprocess, addr, &bp.content, 1, &dwRead);
//	//4.写入int3
//	WriteProcessMemory(hprocess, addr, &cc, 1, &dwRead);
//	//5.回复内存属性
//	VirtualProtectEx(hprocess, addr, 1, oldProtect, &protect);
//	//6.关闭进程句柄
//	CloseHandle(hprocess);
//	bps.push_back(bp);
//	return true;
//}
////打开文件
//bool processFile(){
//	STARTUPINFO si = { sizeof(si) };
//	PROCESS_INFORMATION ps = { 0 };
//	BOOL bret = TRUE;
//
//	//1. 以调试方式打开进程
//	bret = CreateProcess(
//		szFile, //进程名
//		NULL,		//命令行参数
//		NULL,		//进程安全属性
//		NULL,		//线程安全属性
//		FALSE,		//是否继承句柄
//		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,		//只调试这个程序，新控制台
//		NULL,		//环境变量
//		NULL,		//进程运行目录
//		&si,		//进程配置信息
//		&ps);		//进程信息
//
//	if (bret == FALSE)
//	{
//		printf(" create process error \n");
//		return 0;
//	}
//	// 2.循环等待调试事件
//	return TRUE;
//}
//// 处理异常分发

//
////异常
//DWORD OnExecptionDispath()
//{
//	//获取异常代码
//	DWORD Code = pexcption->ExceptionRecord.ExceptionCode;
//	//异常地址
//	LPVOID ExecptionAddr = pexcption->ExceptionRecord.ExceptionAddress;
//
//	//状态，是否处理这个异常
//	DWORD Status = DBG_EXCEPTION_NOT_HANDLED;
//
//	//分别处理异常
//	switch (Code)
//	{
//		//访问异常
//	case EXCEPTION_ACCESS_VIOLATION:
//
//		break;
//		//int 3 软件异常
//	case  EXCEPTION_BREAKPOINT:
//		cout << "system";
//		//Status = OnBreakPointHandler(pexcption);
//		break;
//		//单步异常
//	case EXCEPTION_SINGLE_STEP:
//		//恢复int 3断点
//		//setBreakPointAll();
//		break;
//	}
//	return  Status;
//}

#include"dbg.h"

//int main(){
//	
//	/*findFile();
//	bool running = processFile();
//	DWORD StatusCode = DBG_EXCEPTION_NOT_HANDLED;*/
//	bool running = 1;
//	while (running)
//	{
//		WaitForDebugEvent(&g_de, -1);
//		//发生什么调试事件
//		switch (g_de.dwDebugEventCode)
//		{
//		case EXCEPTION_DEBUG_EVENT:     // 异常调试事件
//			//3.处理异常事件	
//			//OnExecptionDispath();
//			//StatusCode = OnExecptionDispath(&g_de.u.Exception);
//			break;
//		case CREATE_THREAD_DEBUG_EVENT: // 线程创建事件
//			printf("线程创建事件触发\n");
//			break;
//		case CREATE_PROCESS_DEBUG_EVENT:// 进程创建事件
//
//			//获取OEP地址
//			addr = g_de.u.CreateProcessInfo.lpStartAddress;
//			pid = g_de.dwProcessId;
//			cout << (DWORD)addr;
//			printf("进程创建事件触发\n");
//			break;
//		case EXIT_THREAD_DEBUG_EVENT:   // 退出线程事件
//			printf("退出线程事件触发\n");
//			break;
//		case EXIT_PROCESS_DEBUG_EVENT:  // 退出进程事件
//			printf("退出进程事件触发\n");
//			running = FALSE; //结束循环
//			break;
//		case LOAD_DLL_DEBUG_EVENT:      // 映射DLL事件
//			printf("映射DLL事件触发\n");
//			break;
//		case UNLOAD_DLL_DEBUG_EVENT:    // 卸载DLL事件 
//			printf("卸载DLL事件触发\n");
//			break;
//		case OUTPUT_DEBUG_STRING_EVENT: // 调试字符串输出事件
//			printf("调试字符串输出事件触发\n");
//			break;
//		case RIP_EVENT:                 // RIP事件(内部错误)
//			break;
//		}
//
//		//4.回复调试子系统
//		ContinueDebugEvent(g_de.dwProcessId, g_de.dwThreadId, StatusCode);
//	}
//	std::cout << szFile;
//}
int main(){
	dbg debug;
	debug.run();
}