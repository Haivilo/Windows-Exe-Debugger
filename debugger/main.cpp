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
//DWORD pid = 0;			//���̼���ʱ������
//enum{
//	cc,
//	ram,
//	hardware
//};
//typedef struct{
//	DWORD type;			//����
//	LPVOID addr;		//�ϵ��ַ
//	BOOL   isEnable;	//�Ƿ����öϵ�
//	BYTE content;		//ԭ������
//}breakpoints;
//
////�������ļ���szFile����
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
//	//1. �򿪽���
//	HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_de.dwProcessId);
//
//	//2.��ȡ�ڴ�
//	ReadProcessMemory(hprocess, addr, buff, 1024, &dwRead);
//	//3.�����
//
//	DISASM disasm = {};
//	disasm.Archi = 0;			//x86���
//	disasm.EIP = (UIntPtr)buff;			//������
//	disasm.VirtualAddr = (UInt64)addr;	//��ʾ��ַ
//	DWORD contlen = 0;
//	contlen = Disasm(&disasm);
//	printf("%08X %s\n", addr, disasm.CompleteInstr);
//	//4.�رս���
//	CloseHandle(hprocess);
//	return contlen;
//}
////������CC�ϵ�
//bool SetCCBreakPoint(LPVOID addr){
//	//�Ƿ��ظ��¶ϵ�
//	for (auto i : bps)
//	{
//		if (addr == i.addr)
//			return false;
//	}
//	//��������ϵ�
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
//	//1.�򿪽��̾��
//	DWORD oldProtect = 0;
//	HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_de.dwProcessId);
//	//2.�޸��ڴ�����
//	VirtualProtectEx(hprocess, addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
//	//3.��ȡԭʼ����
//	ReadProcessMemory(hprocess, addr, &bp.content, 1, &dwRead);
//	//4.д��int3
//	WriteProcessMemory(hprocess, addr, &cc, 1, &dwRead);
//	//5.�ظ��ڴ�����
//	VirtualProtectEx(hprocess, addr, 1, oldProtect, &protect);
//	//6.�رս��̾��
//	CloseHandle(hprocess);
//	bps.push_back(bp);
//	return true;
//}
////���ļ�
//bool processFile(){
//	STARTUPINFO si = { sizeof(si) };
//	PROCESS_INFORMATION ps = { 0 };
//	BOOL bret = TRUE;
//
//	//1. �Ե��Է�ʽ�򿪽���
//	bret = CreateProcess(
//		szFile, //������
//		NULL,		//�����в���
//		NULL,		//���̰�ȫ����
//		NULL,		//�̰߳�ȫ����
//		FALSE,		//�Ƿ�̳о��
//		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,		//ֻ������������¿���̨
//		NULL,		//��������
//		NULL,		//��������Ŀ¼
//		&si,		//����������Ϣ
//		&ps);		//������Ϣ
//
//	if (bret == FALSE)
//	{
//		printf(" create process error \n");
//		return 0;
//	}
//	// 2.ѭ���ȴ������¼�
//	return TRUE;
//}
//// �����쳣�ַ�

//
////�쳣
//DWORD OnExecptionDispath()
//{
//	//��ȡ�쳣����
//	DWORD Code = pexcption->ExceptionRecord.ExceptionCode;
//	//�쳣��ַ
//	LPVOID ExecptionAddr = pexcption->ExceptionRecord.ExceptionAddress;
//
//	//״̬���Ƿ�������쳣
//	DWORD Status = DBG_EXCEPTION_NOT_HANDLED;
//
//	//�ֱ����쳣
//	switch (Code)
//	{
//		//�����쳣
//	case EXCEPTION_ACCESS_VIOLATION:
//
//		break;
//		//int 3 ����쳣
//	case  EXCEPTION_BREAKPOINT:
//		cout << "system";
//		//Status = OnBreakPointHandler(pexcption);
//		break;
//		//�����쳣
//	case EXCEPTION_SINGLE_STEP:
//		//�ָ�int 3�ϵ�
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
//		//����ʲô�����¼�
//		switch (g_de.dwDebugEventCode)
//		{
//		case EXCEPTION_DEBUG_EVENT:     // �쳣�����¼�
//			//3.�����쳣�¼�	
//			//OnExecptionDispath();
//			//StatusCode = OnExecptionDispath(&g_de.u.Exception);
//			break;
//		case CREATE_THREAD_DEBUG_EVENT: // �̴߳����¼�
//			printf("�̴߳����¼�����\n");
//			break;
//		case CREATE_PROCESS_DEBUG_EVENT:// ���̴����¼�
//
//			//��ȡOEP��ַ
//			addr = g_de.u.CreateProcessInfo.lpStartAddress;
//			pid = g_de.dwProcessId;
//			cout << (DWORD)addr;
//			printf("���̴����¼�����\n");
//			break;
//		case EXIT_THREAD_DEBUG_EVENT:   // �˳��߳��¼�
//			printf("�˳��߳��¼�����\n");
//			break;
//		case EXIT_PROCESS_DEBUG_EVENT:  // �˳������¼�
//			printf("�˳������¼�����\n");
//			running = FALSE; //����ѭ��
//			break;
//		case LOAD_DLL_DEBUG_EVENT:      // ӳ��DLL�¼�
//			printf("ӳ��DLL�¼�����\n");
//			break;
//		case UNLOAD_DLL_DEBUG_EVENT:    // ж��DLL�¼� 
//			printf("ж��DLL�¼�����\n");
//			break;
//		case OUTPUT_DEBUG_STRING_EVENT: // �����ַ�������¼�
//			printf("�����ַ�������¼�����\n");
//			break;
//		case RIP_EVENT:                 // RIP�¼�(�ڲ�����)
//			break;
//		}
//
//		//4.�ظ�������ϵͳ
//		ContinueDebugEvent(g_de.dwProcessId, g_de.dwThreadId, StatusCode);
//	}
//	std::cout << szFile;
//}
int main(){
	dbg debug;
	debug.run();
}