#include "dbg.h"

void dbg::findFile()//�ҵ��ļ�
{
	OPENFILENAME ofn;

	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.lpstrFile = szFile;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = L"All\0*.*\0Text\0*.TXT\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	GetOpenFileName(&ofn);
}
bool dbg::processFile(){//���ļ�������
	STARTUPINFO si = { sizeof(si) };
	
	BOOL bret = TRUE;

	//1. �Ե��Է�ʽ�򿪽���
	bret = CreateProcess(
		szFile, //������
		NULL,		//�����в���
		NULL,		//���̰�ȫ����
		NULL,		//�̰߳�ȫ����
		FALSE,		//�Ƿ�̳о��
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,		//ֻ������������¿���̨
		NULL,		//��������
		NULL,		//��������Ŀ¼
		&si,		//����������Ϣ
		&ps);		//������Ϣ

	if (bret == FALSE)
	{
		printf(" create process error \n");
		return 0;
	}
	htread = ps.hThread;
	hprocess = ps.hProcess;
	pid = ps.dwProcessId;

	return TRUE;
}
dbg::dbg():addr(pexcption->ExceptionRecord.ExceptionAddress)//����ʱ���ж��Ǹ��ӻ��Ǵ�
{
	open=1;
	cout << "1: �� 0: ����\n";
	scanf_s("%d", &open);
	while (getchar() != '\n');
	if (open)
	{
	findFile();
	processFile();
	}
	else
	{
		fujiaCC = 1;
		cout << "pid:";
		scanf_s("%d", &pid);
		DebugActiveProcess(pid);
		//hprocess = OpenProcess(THREAD_ALL_ACCESS, 0, pid);
		//htread = OpenThread(THREAD_ALL_ACCESS, 0, tid);
	}
	readExts();
}


dbg::~dbg()
{
}

DWORD dbg::exceptionHandle(){
	//static bool first;
  	DWORD code = pexcption->ExceptionRecord.ExceptionCode;
	DWORD status = DBG_EXCEPTION_NOT_HANDLED;
	switch (code)
	{
		//�����쳣
	case EXCEPTION_ACCESS_VIOLATION:
	{
		//pexcption->ExceptionRecord.ExceptionInformation[0]
		DWORD oldpro;//�Ļ�ԭ������
		VirtualProtectEx(hprocess, (LPVOID)mmmm.addr, 1, mmmm.content, &oldpro);
		//printf("%x", pexcption->ExceptionRecord.ExceptionInformation[1]);
		memjmp = 1;//flag����
		if (pexcption->ExceptionRecord.ExceptionInformation[1] == (DWORD)mmmm.addr)
		{//������˶ϵ�
			if (pexcption->ExceptionRecord.ExceptionInformation[0] == mmmm.type)
			{
				printTxt();
				listen();
				//return DBG_CONTINUE;
			}
		}
		setTF();
		status = DBG_CONTINUE;
	}
	break;
		//setTF();
		//DWORD oldpro;
		//VirtualProtectEx(hprocess, (LPVOID)0x042BC23, 1, PAGE_EXECUTE_READ, &oldpro);
		//VirtualProtectEx(hprocess, (LPVOID)0x042BC23, 1, PAGE_EXECUTE_READ, &oldpro);
		////disableAllpts();
		//memjmp = 1;
		//status = DBG_CONTINUE;
		
		//int 3 ����쳣
	case  EXCEPTION_BREAKPOINT:
	{
		//bool static first = 1;
		if (fujiaCC)//���ӾͲ��õ�һ��������
		{
			printTxt();
			listen();
			fujiaCC = 0;
			first = 0;
			return DBG_CONTINUE;
		}
		if (first)//����һ��
		{
			first = 0;
			return DBG_EXCEPTION_NOT_HANDLED;
		}
		disableAllpts();
		decEip();
		breakpoints conditionbreak= ifCondition();
		if (conditionbreak.addr)//����
		{
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			if (context.Eax == conditionbreak.value){//����
				int3jmp = 1;
				setTF();
				printTxt();
				listen();
			}
			else//û��
			{
				int3jmp = 1;
				setTF();
			}
		}
		else
		{
			char buff[1024] = {};
			ReadProcessMemory(hprocess, addr, buff, 1024, 0);
			if (buff[0] == 0xffffffcc)//����
			{
				WriteProcessMemory(hprocess, addr, &stepOverContent, 1, 0);
			}
			int3jmp = 1;
			setTF();
			printTxt();
			listen();
		}
		status = DBG_CONTINUE;//step in TF=1 no bool val,go TF=1,+bool val,step over, check, if call:TF=1, bool val, +new CC
		//status = OnBreakPointHandler(pexcption);
		break;
		//�����쳣 
	}
	case EXCEPTION_SINGLE_STEP:
		//�ָ�int 3�ϵ�
		CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
		GetThreadContext(htread, &context);
		PDBG_REG6 p = (PDBG_REG6)&context.Dr6;
		if (p->B0||p->B1||p->B2||p->B3)//hardware
		{
			disableAllpts();
			hdjmp = 1;
			setTF(); 
			printTxt();
			listen();
		}
		else{
			if (int3jmp || hdjmp||memjmp)//�ָ�
			{
				//if (memjmp&&bpExist(addr))
				//{
				//	printTxt();
				//	listen();
				//}
				hdjmp = 0;
				int3jmp = 0;
				memjmp = 0;
			}
			else//TF��TT
			{
				//disableAllpts();
				printTxt();
				listen();

			}
			if (mmmm.addr)//�ָ��ϵ�
			{
				DWORD oldpro;
				VirtualProtectEx(hprocess, (LPVOID)mmmm.addr, 1, PAGE_NOACCESS, &oldpro);
			}
			//printTxt();
			resetAllpts();//�ָ�����

		}
			//setBreakPointAll();
			status = DBG_CONTINUE;
			break;
		
	}
	return  status;
}
DWORD dbg::resetAllpts(){//�ָ�����
	for (auto i:bps)
	{
		switch (i.type){
		case cc: 
		case condition:
			setCC(i.addr);
			break;
		case ram:
			//VirtualProtectEx(hprocess, i.addr, 1, PAGE_NOACCESS, 0);
			break;
		default: break;
		}
	}
	resetHD(1);
	return 1;
}

DWORD dbg::disableAllpts(){//��������
	for (auto i : bps){
		switch (i.type){
		case cc:
		case condition:
			disableCC(i);
			break;
		case ram:
			memReset(i); break;
		case hardware:
		default: break;
		}
	}
	resetHD(0);
	return 1;
}
BYTE dbg::setCC(LPVOID addr){
	//��������ϵ�
	BYTE oldbyte;
	DWORD dwRead;
	DWORD protect;
	DWORD oldProtect;
	char cc = 0xcc;
	//1.�򿪽��̾��
	static bool a = 0;
	//2.�޸��ڴ�����
	VirtualProtectEx(hprocess, addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
	//3.��ȡԭʼ����
	ReadProcessMemory(hprocess, addr, &oldbyte, 1, &dwRead);
	//4.д��int3
	WriteProcessMemory(hprocess, addr, &cc, 1, &dwRead);
	//5.�ظ��ڴ�����
	VirtualProtectEx(hprocess, addr, 1, oldProtect, &protect);
	return oldbyte;
}

void dbg::disableCC(breakpoints& bp){
	BYTE oldbyte;
	DWORD dwRead;
	DWORD protect;
	DWORD oldProtect;
	VirtualProtectEx(hprocess, bp.addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
	//3.��ȡԭʼ����
	ReadProcessMemory(hprocess, bp.addr, &oldbyte, 1, &dwRead);
	//4.д��int3 
	WriteProcessMemory(hprocess, bp.addr, &bp.content, 1, &dwRead);
	//5.�ظ��ڴ�����
	VirtualProtectEx(hprocess, bp.addr, 1, oldProtect, &protect);
}
void dbg::decEip(){
	//eip-1
	CONTEXT context = { CONTEXT_ALL };
	GetThreadContext(htread, &context);
	context.Eip -= 1;
	SetThreadContext(htread, &context);
}
DWORD dbg::printTxt(LPVOID address){
	//��ӡ�����
	if (!address)
	{
		address = addr;
	}
	char buff[1024] = {};
	DWORD dwRead = 0;
	//2.��ȡ�ڴ�
	ReadProcessMemory(hprocess, address, buff, 1024, &dwRead);
	//3.�����
	DISASM disasm = {};
	disasm.Archi = 0;			//x86���
	disasm.EIP = (UIntPtr)buff;			//������
	disasm.VirtualAddr = (UInt64)address;	//��ʾ��ַ
	DWORD contlen = 0;
	contlen = Disasm(&disasm);
	printf("%08X %s\n", address, disasm.CompleteInstr);
	//4.�رս���
	//CloseHandle(hprocess);
	return contlen;
}
void dbg::setOEP(){
	//��oep�ϵ�
	breakpoints bp;
	bp.addr = g_de.u.CreateProcessInfo.lpStartAddress;
	//bp.isEnable = 1;
	bp.type = cc;
	bp.content = setCC(bp.addr);
	bps.push_back(bp);
}
void dbg::run(){//�ʼ����
	bool running = 1;
	DWORD StatusCode = DBG_EXCEPTION_NOT_HANDLED;
	while (running)
	{
		WaitForDebugEvent(&g_de, -1);
		pexcption = &g_de.u.Exception;
		if (!open)//������ʽ
		{
			hprocess = OpenProcess(THREAD_ALL_ACCESS, 0, g_de.dwProcessId);
			htread = OpenThread(THREAD_ALL_ACCESS, 0, g_de.dwThreadId);
			open = 1;
		}
		//����ʲô�����¼�
		switch (g_de.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:     // �쳣�����¼�
			//3.�����쳣�¼�	
			//OnExecptionDispath();
			//StatusCode = OnExecptionDispath(&g_de.u.Exception);
			StatusCode=exceptionHandle();
			break;
		case CREATE_THREAD_DEBUG_EVENT: // �̴߳����¼�
			printf("�̴߳����¼�����\n");
			break;
		case CREATE_PROCESS_DEBUG_EVENT:// ���̴����¼�
			//��ȡOEP��ַ
			//addr = g_de.u.CreateProcessInfo.lpStartAddress;
			//hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_de.dwProcessId);
			
			setOEP();
			cout << (DWORD)g_de.u.CreateProcessInfo.lpStartAddress;;
			printf("���̴����¼�����\n");
			break;
		case EXIT_THREAD_DEBUG_EVENT:   // �˳��߳��¼�
			printf("�˳��߳��¼�����\n");
			break;
		case EXIT_PROCESS_DEBUG_EVENT:  // �˳������¼�
			printf("�˳������¼�����\n");
			running = FALSE; //����ѭ��
			break;
		case LOAD_DLL_DEBUG_EVENT:      // ӳ��DLL�¼�
			printf("ӳ��DLL�¼�����\n");
			break;
		case UNLOAD_DLL_DEBUG_EVENT:    // ж��DLL�¼� 
			printf("ж��DLL�¼�����\n");
			break;
		case OUTPUT_DEBUG_STRING_EVENT: // �����ַ�������¼�
			printf("�����ַ�������¼�����\n");
			break;
		case RIP_EVENT:                 // RIP�¼�(�ڲ�����)
			break;
		}
		StatusCode = DBG_CONTINUE;
		//4.�ظ�������ϵͳ
		ContinueDebugEvent(g_de.dwProcessId, g_de.dwThreadId, StatusCode);
	}
	std::cout << szFile;

}

void dbg::setTF(){
	CONTEXT context = { CONTEXT_ALL };
	GetThreadContext(htread, &context);
	//����Eflages->TF
	((EFLAGS*)&context.EFlags)->TF = 1;
	//�����߳�������
	SetThreadContext(htread, &context);
}
void dbg::listen(){
	//�ȴ��û�����
	while (1)
	{
		char buffer[20] = {};
		char *CmdBuf = nullptr;
		char *NumBuf = nullptr;
		DWORD address = 0;
		printf("������:");
		gets_s(buffer, 20);
		CmdBuf = strtok_s(buffer, " ", &NumBuf);
		sscanf_s(NumBuf, "%x", &address);//��ʽ������
		if (CmdBuf==nullptr)
		{
			continue;
		}
		if (strcmp("bp", CmdBuf) == 0){//�ϵ�
			if (bpExist((LPVOID)address)){
				printf("breakPoint existed");
			}
			else
			{
			breakpoints bp;
			bp.addr = (LPVOID)address;
			//bp.isEnable = 1;
			bp.type = cc;
			bp.content = setCC(bp.addr);
			bps.push_back(bp);
			}
		}
		if (strcmp("t", CmdBuf) == 0)//DOF7
		{
			disableAllpts();
			setTF();
			noTFreset();
			return;
		}
		if (strcmp("tt", CmdBuf) == 0){//���������call
			DWORD len = 0;
			if (isCall(len) ){
				if (!bpExist((LPVOID)address))
				{
				stepOverContent = setCC((LPVOID)((DWORD)addr + len));
				}
			}
			else
			{
				disableAllpts();
				noTFreset();
				setTF(); 
				/*breakpoints bp;
				bp.addr = (LPVOID)address;
				bp.isEnable = 1;
				bp.type = cc;
				bp.content = setCC((LPVOID)address);
				bps.push_back(bp);*/
			}
			return;

		}
		if (strcmp("mme", CmdBuf) == 0)//�ڴ棬r��e��w
		{
			//memBp(address);
			//DWORD oldProtect;
			//mmmm.addr = (LPVOID)address;
			//mmmm.type = ram;
			//VirtualProtectEx(hprocess, (LPVOID)mmmm.addr, 1, PAGE_NOACCESS, &oldProtect);
			//mmmm.content = oldProtect;
			////MemBreakAddr = addr;
			////	SetMemBreak();
			memBp(address, 8);
		}		
		if (strcmp("mmr", CmdBuf) == 0)
		{
			////memBp(address);
			//DWORD oldProtect;
			//mmmm.addr = (LPVOID)address;
			//mmmm.type = ram;
			//VirtualProtectEx(hprocess, (LPVOID)mmmm.addr, 1, PAGE_NOACCESS, &oldProtect);
			//mmmm.content = oldProtect;
			////MemBreakAddr = addr;
			////	SetMemBreak();
			memBp(address, 0);

		}
		if (strcmp("mmw", CmdBuf) == 0)
		{
			//memBp(address);
			//DWORD oldProtect;
			//mmmm.addr = (LPVOID)address;
			//mmmm.type = ram;
			//VirtualProtectEx(hprocess, (LPVOID)mmmm.addr, 1, PAGE_NOACCESS, &oldProtect);
			//mmmm.content = oldProtect;
			////MemBreakAddr = addr;
			////	SetMemBreak();
			memBp(address, 1);

		}if (strcmp("hd", CmdBuf) == 0)//ִ��
		{
			regisertHardE(address);
			//	SetHardBreak(addr);
		}
		if (strcmp("hdrw", CmdBuf) == 0){//����
			regisertHardRW(address, 3, 1);
		}		
		if (strcmp("hdw", CmdBuf) == 0){//д��
			regisertHardRW(address, 1, 1);
		}
		if (strcmp("g", CmdBuf) == 0)
		{
			return;
		}	
		if (strcmp("cbp", CmdBuf) == 0)//����
		{
			conditionBp(address);
			while (getchar() != '\n');
		}
		if (strcmp("r", CmdBuf) == 0){//�Ĵ�����Ϣ
			showInfo();
		}
		if (strcmp("eax", CmdBuf) == 0){//change register info
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Eax = address;
			//�����߳�������
			SetThreadContext(htread, &context);
		}
		if (strcmp("ebx", CmdBuf) == 0){
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Ebx = address;
			//�����߳�������
			SetThreadContext(htread, &context);
		}
		if (strcmp("ecx", CmdBuf) == 0){
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Ecx = address;
			//�����߳�������
			SetThreadContext(htread, &context);
		}
		if (strcmp("edx", CmdBuf) == 0){
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Edx = address;
			//�����߳�������
			SetThreadContext(htread, &context);
		}
		if (strcmp("edi", CmdBuf) == 0){
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Edi = address;
			//�����߳�������
			SetThreadContext(htread, &context);
		}
		if (strcmp("esi", CmdBuf) == 0){
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Esi = address;
			//�����߳�������
			SetThreadContext(htread, &context);
		}
		if (strcmp("eip", CmdBuf) == 0){
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Eip = address;
			//�����߳�������
			SetThreadContext(htread, &context);
		}
		if (strcmp("ebp", CmdBuf) == 0){
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Ebp = address;
			//�����߳�������
			SetThreadContext(htread, &context);
		}
		if (strcmp("esp", CmdBuf) == 0){
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Esp = address;
			//�����߳�������
			SetThreadContext(htread, &context);
		}
		if (strcmp("ss", CmdBuf) == 0){
			readStack();
		}
		if (strcmp("readmem", CmdBuf) == 0){
			readData(address);

		}
		if (strcmp("writemem", CmdBuf) == 0){

			changeData(address);
		}
		if (strcmp("show", CmdBuf) == 0){
			printTxt(LPVOID(address));
		}
		if (strcmp("edit", CmdBuf) == 0){
			writeCode(address);
		}
		if (strcmp("module", CmdBuf) == 0){
			printModules();
		}
		if (strcmp("peb", CmdBuf) == 0){
			hidePEB();
		}
		if (strcmp("hook", CmdBuf) == 0)
		{
			hook();
		}
		if (strcmp("extension", CmdBuf) == 0)
		{
			extensions();
		}
		if (strcmp("dump", CmdBuf) == 0)
		{
			dump(address);
		}
	}
	return;
}
bool dbg::isCall(DWORD &length){//�ж��ǲ���call
	char buff[1024] = {};
	DWORD dwRead = 0;
	//2.��ȡ�ڴ�
	ReadProcessMemory(hprocess, addr, buff, 1024, &dwRead);
	//3.�����
	DISASM disasm = {};
	disasm.Archi = 0;			//x86���
	disasm.EIP = (UIntPtr)buff;			//������
	disasm.VirtualAddr = (UInt64)addr;	//��ʾ��ַ
	
	length = Disasm(&disasm);
	char* code = disasm.CompleteInstr;
	code[4] = 0;
	return !strcmp(code, "call");
	//printf("%08X %s\n", addr, disasm.CompleteInstr);
	//4.�رս���
	//CloseHandle(hprocess);
	//return contlen;
}

bool dbg::bpExist(LPVOID addr){
	for (auto i:bps)
	{
		if (i.addr == addr)
			return 1;
	}
	return 0;
}
DWORD dbg::setBPHardE(DWORD addr){//����Ӳ��
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(htread, &context);
	PDBG_REG7 p = (PDBG_REG7)&context.Dr7;
	if (p->L0==0)//�ж���û��Ӳ��
	{
		p->L0 = 1;
		context.Dr0 = addr;
		p->RW0 = 0;
		p->LEN0 = 0;
	}
	else if (p->L1 == 0){
		p->L1 = 1;
		context.Dr1 = addr;
		p->RW1 = 0;
		p->LEN1 = 0;
	}
	else if (p->L2 == 0){
		p->L2 = 1;
		context.Dr2 = addr;
		p->RW2 = 0;
		p->LEN2 = 0;
	}
	else if (p->L3 == 0){
		p->L3 = 1;
		context.Dr3 = addr;
		p->RW3 = 0;
		p->LEN3 = 0;
	}
	else
	{
		return 0;
	}
	SetThreadContext(htread, &context);
	return addr;
}
DWORD dbg::setBPHardRW(DWORD addr,DWORD type,DWORD len){//��д�ϵ�
	if (len==1)//��������
	{
		addr = addr - addr % 2;
	}else if(len == 3){
		addr = addr - addr % 4;
	}
	else if (len > 3)
	{
		return 0;
	}
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(htread, &context);
	PDBG_REG7 p = (PDBG_REG7)&context.Dr7;
	if (p->L0 == 0)
	{
		p->L0 = 1;
		context.Dr0 = addr;
		p->RW0 = type;
		p->LEN0 = len;
	}
	else if (p->L1 == 0){
		p->L1 = 1;
		context.Dr1 = addr;
		p->RW1 = type;
		p->LEN1 = len;
	}
	else if (p->L2 == 0){
		p->L2 = 1;
		context.Dr2 = addr;
		p->RW2 = type;
		p->LEN2 = len;
	}
	else if (p->L3 == 0){
		p->L3 = 1;
		context.Dr3 = addr;
		p->RW3 = type;
		p->LEN3 = len;
	}
	else
	{
		return 0;
	}
	SetThreadContext(htread, &context);
	return addr;
}
bool dbg::regisertHardE(DWORD addr){//ע��ϵ㣬push��vector
	breakpoints bp;
	bp.addr = (LPVOID)setBPHardE(addr);
	if (bp.addr)
	{
	bp.type = hardware;
	bps.push_back(bp);
	return bp.addr;
	}
	else{
		printf("hd bp is full");
		return 0;
	}
}

void dbg::resetHD(bool b){//����b����disable���߿���
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(htread, &context);
	PDBG_REG7 p = (PDBG_REG7)&context.Dr7;
	if (context.Dr0)
	{
		p->L0 = b;
	}
	if (context.Dr1)
	{
		p->L1 = b;
	}
	if (context.Dr2)
	{
		p->L2 = b;
	}
	if (context.Dr3)
	{
		p->L3 = b;
	}
	SetThreadContext(htread, &context);
}

void dbg::noTFreset(){//��������TF
	int3jmp = 0;
	hdjmp = 0;
	memjmp = 0;
}
bool dbg::regisertHardRW(DWORD addr, DWORD type, DWORD len){//ע��Ӳ����д
	breakpoints bp;
	bp.addr = (LPVOID)setBPHardRW(addr, type, len);
	if (bp.addr)
	{
		bp.type = hardware;
		bps.push_back(bp);
		return bp.addr;
	}
	else{
		printf("hd bp is full");
		return 0;
	}
}
bool dbg::memBp(DWORD addr,DWORD type){//�ڴ�ϵ㣬������������
	//DWORD oldProtect;
	//breakpoints bp;
	//bp.addr = (LPVOID)addr;
	//bp.type = ram;
	//VirtualProtectEx(hprocess, (LPVOID)addr, 1, PAGE_NOACCESS, &oldProtect);
	//bp.content = oldProtect;
	//bps.push_back(bp);
	//return 1;


	//memBp(address);
	DWORD oldProtect;
	VirtualProtectEx(hprocess, (LPVOID)mmmm.addr, 1, mmmm.content, &oldProtect);
	mmmm.addr = (LPVOID)addr;
	mmmm.type = type;
	VirtualProtectEx(hprocess, (LPVOID)mmmm.addr, 1, PAGE_NOACCESS, &oldProtect);
	mmmm.content = oldProtect;
	//MemBreakAddr = addr;
	//	SetMemBreak();
	//VirtualProtectEx(hprocess, (LPVOID)addr, 1, oldProtect, &protect);
	return 1;
}

void dbg::memReset(breakpoints& bp){//�������ã�����vector��Ԫ��
	DWORD oldpro;
	VirtualProtectEx(hprocess, bp.addr, 1, bp.content,&oldpro);

}

void dbg::conditionBp(DWORD addr){//���������ϵ�
	breakpoints bp;
	bp.type = condition;
	bp.addr = (LPVOID)addr;
	bp.content = setCC((LPVOID)addr);
	printf("eax: ");
	int eax;
	scanf_s("%d", &eax);
	bp.value = eax;
	bps.push_back(bp);
}
breakpoints dbg::ifCondition(){//�ж��ǲ��������ϵ㣬��int3���µ�ʱ��
	for (auto i : bps)
	{
		if (i.type==condition&&i.addr==addr)
		{
			return i;
		}
	}
		return{0,0,0,0};
}
//�������һЩ�鿴��Ϣ
void dbg::showInfo(){
	CONTEXT context = { CONTEXT_ALL };
	GetThreadContext(htread, &context);
	printf("Eax:%x,Ebp:%x,Ebx:%x,Ecx:%x\nEdi:%x,Edx:%x,Eip:%x,Esi:%x\n",
		context.Eax, context.Ebp, context.Ebx, context.Ecx, context.Edi, context.Edx, context.Eip, context.Esi, context.Esp);
}
void dbg::readStack(){
	CONTEXT context = { CONTEXT_ALL };
	GetThreadContext(htread, &context);
	BYTE buff[512];
	DWORD rd = 0;
	ReadProcessMemory(hprocess, (LPCVOID)context.Esp, buff, 512, &rd);
	for (size_t i = 0; i < 10; i++)
	{
		printf("%08x %08x\n", context.Esp +i*4 ,((DWORD*)buff)[i]);
	}
}
void dbg::changeData(DWORD address){
	DWORD oldProtect; 
	DWORD data;
	DWORD dwread;
	//DWORD oldbyte;
	printf("data: ");
	scanf_s("%02X", &data);
	while (getchar() != '\n');
	VirtualProtectEx(hprocess, (LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
	//3.��ȡԭʼ����
	//ReadProcessMemory(hprocess, addr, &oldbyte, 1, &dwRead);
	//4.д��int3
	WriteProcessMemory(hprocess, (LPVOID)address, &data, 1, &dwread);
	//5.�ظ��ڴ�����
	VirtualProtectEx(hprocess, (LPVOID) address, 1, oldProtect, &oldProtect);
	}
void dbg::readData(DWORD address){
	DWORD oldProtect;
	DWORD data;
	DWORD dwread;
	DWORD oldbyte;
	printf("length: ");
	scanf_s("%08X", &data);
	while (getchar() != '\n');
	for (size_t i = 0; i < data; i++)
	{
	VirtualProtectEx(hprocess, (LPVOID)(address+i), 1, PAGE_EXECUTE_READWRITE, &oldProtect);
	//3.��ȡԭʼ����
	ReadProcessMemory(hprocess, (LPVOID)(address + i), &oldbyte, 1, &dwread);
	oldbyte = oldbyte&0xFF;
	printf("%02x ", oldbyte);
	//4.д��int3
	//WriteProcessMemory(hprocess, (LPVOID)address, &data, 1, &dwread);
	//5.�ظ��ڴ�����
	VirtualProtectEx(hprocess, (LPVOID)(address + i), 1, oldProtect, &oldProtect);
	}
	printf("\n");
}

void dbg::writeCode(DWORD address){
	ks_engine *pengine = NULL;
	if (KS_ERR_OK != ks_open(KS_ARCH_X86, KS_MODE_32, &pengine))
	{
		printf("����������ʼ��ʧ��\n");
		return;
	}

	unsigned char* opcode = NULL; // ���õ���opcode�Ļ������׵�ַ
	unsigned int nOpcodeSize = 0; // ��������opcode���ֽ���

	char asmCode[100] = { "" };
	//getchar();
	gets_s(asmCode, 100);

	int nRet = 0; // ���溯���ķ���ֵ�������жϺ����Ƿ�ִ�гɹ�


	size_t stat_count = 0; // ����ɹ�����ָ�������

	nRet = ks_asm(pengine, /* �����������ͨ��ks_open�����õ�*/
		asmCode, /*Ҫת���Ļ��ָ��*/
		address, /*���ָ�����ڵĵ�ַ*/
		&opcode,/*�����opcode*/
		&nOpcodeSize,/*�����opcode���ֽ���*/
		&stat_count /*����ɹ�����ָ�������*/
		);

	// ����ֵ����-1ʱ��������
	if (nRet == -1)
	{
		// ���������Ϣ
		// ks_errno ��ô�����
		// ks_strerror ��������ת�����ַ���������������ַ���
		printf("������Ϣ��%s\n", ks_strerror(ks_errno(pengine)));
		return;
	}

	printf("һ��ת����%d��ָ��\n", stat_count);

	//����ֻ�ܽ�opcodeд���ڴ������Ч
	SIZE_T temp;
	WriteProcessMemory(hprocess, (LPVOID)address, opcode, nOpcodeSize, &temp);

	int a = 10;

	// �ͷſռ�
	ks_free(opcode);

	// �رվ��
	ks_close(pengine);

}
void dbg::printModules(){//��ӡģ��
	static bool dllss = 1;
	DWORD size;
	EnumProcessModulesEx(hprocess, 0, 0, &size, LIST_MODULES_ALL);
	HMODULE* outMod = (HMODULE*)new char[size];
	EnumProcessModulesEx(hprocess, outMod, size, &size, LIST_MODULES_ALL);
	WCHAR modName[MAX_PATH];
	for (int i = 0; i < size / sizeof(HMODULE); i++)
	{
		MODULEINFO info = { 0 };
		GetModuleInformation(hprocess, outMod[i], &info, sizeof(info));
		GetModuleFileNameEx(hprocess, outMod[i], modName, MAX_PATH);
		cout << info.EntryPoint << endl << info.lpBaseOfDll << endl << info.SizeOfImage << endl;
		printf("%ls\n", modName);
		//if (dllss)
		//{
		//dlls a;
		//lstrcpy(a.name, modName);
		//a.address = info.lpBaseOfDll;
		//dllary.push_back(a);
		//exportLs(a.address);
		//}
	}
		//dllss = 0;
}
//����EPB
void dbg::hidePEB()
{
	//����������

	//���̵Ļ�����Ϣ
	DWORD dwRead;
	PROCESS_BASIC_INFORMATION base;
	NtQueryInformationProcess(hprocess,
		ProcessBasicInformation,
		&base,
		sizeof(base),
		&dwRead);

	//��ȡĿ�����PEB
	PEB peb = { 0 };
	ReadProcessMemory(hprocess,
		base.PebBaseAddress,
		&peb,
		sizeof(peb), &dwRead);
	//�޸�PEB,д�ؽ���
	peb.BeingDebugged = 0;
	WriteProcessMemory(hprocess,
		base.PebBaseAddress,
		&peb,
		sizeof(peb), &dwRead);
}
void dbg::hook(){


	// 2. ��ȡĿ����̵ľ��
	
	char IatHookDllName[111] = "C:\\Users\\Rongan Guo\\Documents\\Visual Studio 2013\\Projects\\ConsoleApplication24\\Debug\\ConsoleApplication24.dll";
	// 3. ��Ŀ�����������һ��ռ�[��ΪLoadLibrary�Ĳ���]
	LPVOID Buffer = VirtualAllocEx(hprocess, NULL, 0x100,
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// 4. ��ռ���д������[dll����]
	SIZE_T RealWrite = 0;

	WriteProcessMemory(hprocess, Buffer, IatHookDllName, strlen(IatHookDllName) + 1, &RealWrite);

	// 5. ����Զ���߳�, �ؼ����� LoadLibrary
	//    ע��: �������ַ����ͺ� LoadLibrary ��������Ҫ����һ��
	HANDLE Thread = CreateRemoteThread(hprocess, NULL, NULL,
		(LPTHREAD_START_ROUTINE)LoadLibraryA, Buffer, NULL, NULL);

}
void dbg::extensions(){//������м��������ѡ�о��õ�
	for (size_t i = 0; i < exs.size(); i++)
	{
		printf("%d:%s\n",i, exs[i]->name());
	}
	int num=-1;
	scanf_s("%d", &num);
	while (getchar() != '\n');
	if (num<exs.size()&&num>-1)
	{
		exs[num]->output();
	}
}
void dbg::readExts(){
	WIN32_FIND_DATA   wd = {};
	TCHAR dllPath[MAX_PATH] = {};

	//������ǰĿ¼�� plugin �µ�dll
	//HMODULE mod = LoadLibrary(L"C:\\Users\\Rongan Guo\\Documents\\Visual Studio 2013\\Projects\\ConsoleApplication24\\Debug\\ConsoleApplication24.dll");

	HANDLE hfile = FindFirstFile(L"C:\\Users\\Rongan Guo\\Documents\\Visual Studio 2013\\Projects\\debugger\\plugin\\*", &wd);
	do
	{
		//���������ļ���
		if (wcscmp(wd.cFileName, L".") == 0 || wcscmp(wd.cFileName, L"..") == 0)
		{
			continue;
		}

		//���Լ���dll
		wsprintf(dllPath, L"C:\\Users\\Rongan Guo\\Documents\\Visual Studio 2013\\Projects\\debugger\\plugin\\%s", wd.cFileName);
		HMODULE mod = LoadLibrary(dllPath);
		//HMODULE mod = LoadLibrary(L"C:\\Users\\Rongan Guo\\Documents\\Visual Studio 2013\\Projects\\ConsoleApplication24\\Debug\\ConsoleApplication24.dll");

		if (mod == NULL)
		{
			continue;
		}
		//��ȡdll�����ĺ�����ַ
		outp pobj = (outp)GetProcAddress(mod, "returnExtensions");
		//����������
		if (pobj == NULL)
		{
			FreeLibrary(mod);
			continue;
		}
		exs.push_back(pobj());

	} while (FindNextFile(hfile, &wd));
}
void dbg::dump(DWORD address){
	char p[37] = "C:\\Users\\Rongan Guo\\Desktop\\123.txt";
	HANDLE File = CreateFileA(p, GENERIC_ALL, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD a = 0;
	DWORD oldProtect;
	DWORD len;
	DWORD dwread;
	byte oldbyte[1024];
	printf("length: ");
	scanf_s("%08X", &len);
	while (getchar() != '\n');
	VirtualProtectEx(hprocess, (LPVOID)(address), len, PAGE_EXECUTE_READWRITE, &oldProtect);
		//3.��ȡԭʼ����
	ReadProcessMemory(hprocess, (LPVOID)(address), &oldbyte, len, &dwread);
	VirtualProtectEx(hprocess, (LPVOID)(address),len, oldProtect, &oldProtect);
	
	//printf("\n");
	WriteFile(File, oldbyte, len, &a, 0);
	//WriteFile(File, "\0", 1, 0, 0);

	CloseHandle(File);
}
void dbg::exportLs(LPVOID addr){

	BYTE entry[10000];
	DWORD oldProtect;
	DWORD data;
	DWORD dwread;
	DWORD oldbyte;
	VirtualProtectEx(hprocess, (LPVOID)(addr), 10000, PAGE_EXECUTE_READWRITE, &oldProtect);
	//3.��ȡԭʼ����
	ReadProcessMemory(hprocess, (LPVOID)(addr), &entry, 10000, &dwread);
	VirtualProtectEx(hprocess, (LPVOID)(addr), 10000, oldProtect, &oldProtect);
	
	printf("\n");
	PIMAGE_DOS_HEADER head = (PIMAGE_DOS_HEADER)entry;
	PIMAGE_NT_HEADERS nthead = (PIMAGE_NT_HEADERS)(head->e_lfanew + entry);
	IMAGE_OPTIONAL_HEADER ophead = nthead->OptionalHeader;
	IMAGE_FILE_HEADER fhead = nthead->FileHeader;
	PIMAGE_SECTION_HEADER secfirst = IMAGE_FIRST_SECTION(nthead);
	for (int i = 0; i < fhead.NumberOfSections; i++)
	{
		secfirst++;
	}
	IMAGE_DATA_DIRECTORY* exportAry = ophead.DataDirectory;
	DWORD rvaExport = exportAry[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	//DWORD wq = F2A(nthead, rvaExport);
	DWORD foaExport = rvaExport + (DWORD)entry;
	auto import = (PIMAGE_IMPORT_DESCRIPTOR)foaExport;
	while (import->OriginalFirstThunk){
		//ѭ��PIMAGE_IMPORT_DESCRIPTOR
		auto INT = (PIMAGE_THUNK_DATA32)(import->OriginalFirstThunk + (DWORD)entry);
		while (INT->u1.Ordinal){
			//ѭ��INT
			if (INT->u1.Ordinal & 0x8000000){
				//��λΪ1
				printf("%x", INT->u1.Ordinal & 0xFFFF);
			}
			else
			{
				//���Ƶ���
				auto nameStruct = (PIMAGE_IMPORT_BY_NAME)( INT->u1.Ordinal + (DWORD)entry);
				printf("%x,%s\n", nameStruct->Hint, nameStruct->Name);
			}
			INT++;
		}
		import++;
	}
}