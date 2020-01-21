#include "dbg.h"

void dbg::findFile()//找到文件
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
bool dbg::processFile(){//打开文件，存句柄
	STARTUPINFO si = { sizeof(si) };
	
	BOOL bret = TRUE;

	//1. 以调试方式打开进程
	bret = CreateProcess(
		szFile, //进程名
		NULL,		//命令行参数
		NULL,		//进程安全属性
		NULL,		//线程安全属性
		FALSE,		//是否继承句柄
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,		//只调试这个程序，新控制台
		NULL,		//环境变量
		NULL,		//进程运行目录
		&si,		//进程配置信息
		&ps);		//进程信息

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
dbg::dbg():addr(pexcption->ExceptionRecord.ExceptionAddress)//构造时候判断是附加还是打开
{
	open=1;
	cout << "1: 打开 0: 附加\n";
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
		//访问异常
	case EXCEPTION_ACCESS_VIOLATION:
	{
		//pexcption->ExceptionRecord.ExceptionInformation[0]
		DWORD oldpro;//改回原来属性
		VirtualProtectEx(hprocess, (LPVOID)mmmm.addr, 1, mmmm.content, &oldpro);
		//printf("%x", pexcption->ExceptionRecord.ExceptionInformation[1]);
		memjmp = 1;//flag设置
		if (pexcption->ExceptionRecord.ExceptionInformation[1] == (DWORD)mmmm.addr)
		{//如果中了断点
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
		
		//int 3 软件异常
	case  EXCEPTION_BREAKPOINT:
	{
		//bool static first = 1;
		if (fujiaCC)//附加就不用第一次跳过了
		{
			printTxt();
			listen();
			fujiaCC = 0;
			first = 0;
			return DBG_CONTINUE;
		}
		if (first)//跳第一次
		{
			first = 0;
			return DBG_EXCEPTION_NOT_HANDLED;
		}
		disableAllpts();
		decEip();
		breakpoints conditionbreak= ifCondition();
		if (conditionbreak.addr)//条件
		{
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			if (context.Eax == conditionbreak.value){//命中
				int3jmp = 1;
				setTF();
				printTxt();
				listen();
			}
			else//没有
			{
				int3jmp = 1;
				setTF();
			}
		}
		else
		{
			char buff[1024] = {};
			ReadProcessMemory(hprocess, addr, buff, 1024, 0);
			if (buff[0] == 0xffffffcc)//步过
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
		//单步异常 
	}
	case EXCEPTION_SINGLE_STEP:
		//恢复int 3断点
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
			if (int3jmp || hdjmp||memjmp)//恢复
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
			else//TF或TT
			{
				//disableAllpts();
				printTxt();
				listen();

			}
			if (mmmm.addr)//恢复断点
			{
				DWORD oldpro;
				VirtualProtectEx(hprocess, (LPVOID)mmmm.addr, 1, PAGE_NOACCESS, &oldpro);
			}
			//printTxt();
			resetAllpts();//恢复所有

		}
			//setBreakPointAll();
			status = DBG_CONTINUE;
			break;
		
	}
	return  status;
}
DWORD dbg::resetAllpts(){//恢复所有
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

DWORD dbg::disableAllpts(){//禁用所有
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
	//保存软件断点
	BYTE oldbyte;
	DWORD dwRead;
	DWORD protect;
	DWORD oldProtect;
	char cc = 0xcc;
	//1.打开进程句柄
	static bool a = 0;
	//2.修改内存属性
	VirtualProtectEx(hprocess, addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
	//3.读取原始数据
	ReadProcessMemory(hprocess, addr, &oldbyte, 1, &dwRead);
	//4.写入int3
	WriteProcessMemory(hprocess, addr, &cc, 1, &dwRead);
	//5.回复内存属性
	VirtualProtectEx(hprocess, addr, 1, oldProtect, &protect);
	return oldbyte;
}

void dbg::disableCC(breakpoints& bp){
	BYTE oldbyte;
	DWORD dwRead;
	DWORD protect;
	DWORD oldProtect;
	VirtualProtectEx(hprocess, bp.addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
	//3.读取原始数据
	ReadProcessMemory(hprocess, bp.addr, &oldbyte, 1, &dwRead);
	//4.写入int3 
	WriteProcessMemory(hprocess, bp.addr, &bp.content, 1, &dwRead);
	//5.回复内存属性
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
	//打印出汇编
	if (!address)
	{
		address = addr;
	}
	char buff[1024] = {};
	DWORD dwRead = 0;
	//2.读取内存
	ReadProcessMemory(hprocess, address, buff, 1024, &dwRead);
	//3.反汇编
	DISASM disasm = {};
	disasm.Archi = 0;			//x86汇编
	disasm.EIP = (UIntPtr)buff;			//缓冲区
	disasm.VirtualAddr = (UInt64)address;	//显示地址
	DWORD contlen = 0;
	contlen = Disasm(&disasm);
	printf("%08X %s\n", address, disasm.CompleteInstr);
	//4.关闭进程
	//CloseHandle(hprocess);
	return contlen;
}
void dbg::setOEP(){
	//设oep断点
	breakpoints bp;
	bp.addr = g_de.u.CreateProcessInfo.lpStartAddress;
	//bp.isEnable = 1;
	bp.type = cc;
	bp.content = setCC(bp.addr);
	bps.push_back(bp);
}
void dbg::run(){//最开始函数
	bool running = 1;
	DWORD StatusCode = DBG_EXCEPTION_NOT_HANDLED;
	while (running)
	{
		WaitForDebugEvent(&g_de, -1);
		pexcption = &g_de.u.Exception;
		if (!open)//附加形式
		{
			hprocess = OpenProcess(THREAD_ALL_ACCESS, 0, g_de.dwProcessId);
			htread = OpenThread(THREAD_ALL_ACCESS, 0, g_de.dwThreadId);
			open = 1;
		}
		//发生什么调试事件
		switch (g_de.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:     // 异常调试事件
			//3.处理异常事件	
			//OnExecptionDispath();
			//StatusCode = OnExecptionDispath(&g_de.u.Exception);
			StatusCode=exceptionHandle();
			break;
		case CREATE_THREAD_DEBUG_EVENT: // 线程创建事件
			printf("线程创建事件触发\n");
			break;
		case CREATE_PROCESS_DEBUG_EVENT:// 进程创建事件
			//获取OEP地址
			//addr = g_de.u.CreateProcessInfo.lpStartAddress;
			//hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_de.dwProcessId);
			
			setOEP();
			cout << (DWORD)g_de.u.CreateProcessInfo.lpStartAddress;;
			printf("进程创建事件触发\n");
			break;
		case EXIT_THREAD_DEBUG_EVENT:   // 退出线程事件
			printf("退出线程事件触发\n");
			break;
		case EXIT_PROCESS_DEBUG_EVENT:  // 退出进程事件
			printf("退出进程事件触发\n");
			running = FALSE; //结束循环
			break;
		case LOAD_DLL_DEBUG_EVENT:      // 映射DLL事件
			printf("映射DLL事件触发\n");
			break;
		case UNLOAD_DLL_DEBUG_EVENT:    // 卸载DLL事件 
			printf("卸载DLL事件触发\n");
			break;
		case OUTPUT_DEBUG_STRING_EVENT: // 调试字符串输出事件
			printf("调试字符串输出事件触发\n");
			break;
		case RIP_EVENT:                 // RIP事件(内部错误)
			break;
		}
		StatusCode = DBG_CONTINUE;
		//4.回复调试子系统
		ContinueDebugEvent(g_de.dwProcessId, g_de.dwThreadId, StatusCode);
	}
	std::cout << szFile;

}

void dbg::setTF(){
	CONTEXT context = { CONTEXT_ALL };
	GetThreadContext(htread, &context);
	//设置Eflages->TF
	((EFLAGS*)&context.EFlags)->TF = 1;
	//设置线程上下文
	SetThreadContext(htread, &context);
}
void dbg::listen(){
	//等待用户输入
	while (1)
	{
		char buffer[20] = {};
		char *CmdBuf = nullptr;
		char *NumBuf = nullptr;
		DWORD address = 0;
		printf("请输入:");
		gets_s(buffer, 20);
		CmdBuf = strtok_s(buffer, " ", &NumBuf);
		sscanf_s(NumBuf, "%x", &address);//格式化输入
		if (CmdBuf==nullptr)
		{
			continue;
		}
		if (strcmp("bp", CmdBuf) == 0){//断点
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
		if (strcmp("tt", CmdBuf) == 0){//步过，检查call
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
		if (strcmp("mme", CmdBuf) == 0)//内存，r，e，w
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

		}if (strcmp("hd", CmdBuf) == 0)//执行
		{
			regisertHardE(address);
			//	SetHardBreak(addr);
		}
		if (strcmp("hdrw", CmdBuf) == 0){//访问
			regisertHardRW(address, 3, 1);
		}		
		if (strcmp("hdw", CmdBuf) == 0){//写入
			regisertHardRW(address, 1, 1);
		}
		if (strcmp("g", CmdBuf) == 0)
		{
			return;
		}	
		if (strcmp("cbp", CmdBuf) == 0)//条件
		{
			conditionBp(address);
			while (getchar() != '\n');
		}
		if (strcmp("r", CmdBuf) == 0){//寄存器信息
			showInfo();
		}
		if (strcmp("eax", CmdBuf) == 0){//change register info
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Eax = address;
			//设置线程上下文
			SetThreadContext(htread, &context);
		}
		if (strcmp("ebx", CmdBuf) == 0){
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Ebx = address;
			//设置线程上下文
			SetThreadContext(htread, &context);
		}
		if (strcmp("ecx", CmdBuf) == 0){
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Ecx = address;
			//设置线程上下文
			SetThreadContext(htread, &context);
		}
		if (strcmp("edx", CmdBuf) == 0){
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Edx = address;
			//设置线程上下文
			SetThreadContext(htread, &context);
		}
		if (strcmp("edi", CmdBuf) == 0){
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Edi = address;
			//设置线程上下文
			SetThreadContext(htread, &context);
		}
		if (strcmp("esi", CmdBuf) == 0){
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Esi = address;
			//设置线程上下文
			SetThreadContext(htread, &context);
		}
		if (strcmp("eip", CmdBuf) == 0){
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Eip = address;
			//设置线程上下文
			SetThreadContext(htread, &context);
		}
		if (strcmp("ebp", CmdBuf) == 0){
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Ebp = address;
			//设置线程上下文
			SetThreadContext(htread, &context);
		}
		if (strcmp("esp", CmdBuf) == 0){
			CONTEXT context = { CONTEXT_ALL };
			GetThreadContext(htread, &context);
			context.Esp = address;
			//设置线程上下文
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
bool dbg::isCall(DWORD &length){//判断是不是call
	char buff[1024] = {};
	DWORD dwRead = 0;
	//2.读取内存
	ReadProcessMemory(hprocess, addr, buff, 1024, &dwRead);
	//3.反汇编
	DISASM disasm = {};
	disasm.Archi = 0;			//x86汇编
	disasm.EIP = (UIntPtr)buff;			//缓冲区
	disasm.VirtualAddr = (UInt64)addr;	//显示地址
	
	length = Disasm(&disasm);
	char* code = disasm.CompleteInstr;
	code[4] = 0;
	return !strcmp(code, "call");
	//printf("%08X %s\n", addr, disasm.CompleteInstr);
	//4.关闭进程
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
DWORD dbg::setBPHardE(DWORD addr){//设置硬件
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(htread, &context);
	PDBG_REG7 p = (PDBG_REG7)&context.Dr7;
	if (p->L0==0)//判断有没有硬件
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
DWORD dbg::setBPHardRW(DWORD addr,DWORD type,DWORD len){//读写断点
	if (len==1)//对其力度
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
bool dbg::regisertHardE(DWORD addr){//注册断点，push进vector
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

void dbg::resetHD(bool b){//根据b设置disable或者开启
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

void dbg::noTFreset(){//不会跳过TF
	int3jmp = 0;
	hdjmp = 0;
	memjmp = 0;
}
bool dbg::regisertHardRW(DWORD addr, DWORD type, DWORD len){//注册硬件读写
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
bool dbg::memBp(DWORD addr,DWORD type){//内存断点，根据种类设置
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

void dbg::memReset(breakpoints& bp){//重新设置，根据vector的元素
	DWORD oldpro;
	VirtualProtectEx(hprocess, bp.addr, 1, bp.content,&oldpro);

}

void dbg::conditionBp(DWORD addr){//设置条件断电
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
breakpoints dbg::ifCondition(){//判断是不是条件断点，在int3断下的时候
	for (auto i : bps)
	{
		if (i.type==condition&&i.addr==addr)
		{
			return i;
		}
	}
		return{0,0,0,0};
}
//下面就是一些查看信息
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
	//3.读取原始数据
	//ReadProcessMemory(hprocess, addr, &oldbyte, 1, &dwRead);
	//4.写入int3
	WriteProcessMemory(hprocess, (LPVOID)address, &data, 1, &dwread);
	//5.回复内存属性
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
	//3.读取原始数据
	ReadProcessMemory(hprocess, (LPVOID)(address + i), &oldbyte, 1, &dwread);
	oldbyte = oldbyte&0xFF;
	printf("%02x ", oldbyte);
	//4.写入int3
	//WriteProcessMemory(hprocess, (LPVOID)address, &data, 1, &dwread);
	//5.回复内存属性
	VirtualProtectEx(hprocess, (LPVOID)(address + i), 1, oldProtect, &oldProtect);
	}
	printf("\n");
}

void dbg::writeCode(DWORD address){
	ks_engine *pengine = NULL;
	if (KS_ERR_OK != ks_open(KS_ARCH_X86, KS_MODE_32, &pengine))
	{
		printf("反汇编引擎初始化失败\n");
		return;
	}

	unsigned char* opcode = NULL; // 汇编得到的opcode的缓冲区首地址
	unsigned int nOpcodeSize = 0; // 汇编出来的opcode的字节数

	char asmCode[100] = { "" };
	//getchar();
	gets_s(asmCode, 100);

	int nRet = 0; // 保存函数的返回值，用于判断函数是否执行成功


	size_t stat_count = 0; // 保存成功汇编的指令的条数

	nRet = ks_asm(pengine, /* 汇编引擎句柄，通过ks_open函数得到*/
		asmCode, /*要转换的汇编指令*/
		address, /*汇编指令所在的地址*/
		&opcode,/*输出的opcode*/
		&nOpcodeSize,/*输出的opcode的字节数*/
		&stat_count /*输出成功汇编的指令的条数*/
		);

	// 返回值等于-1时反汇编错误
	if (nRet == -1)
	{
		// 输出错误信息
		// ks_errno 获得错误码
		// ks_strerror 将错误码转换成字符串，并返回这个字符串
		printf("错误信息：%s\n", ks_strerror(ks_errno(pengine)));
		return;
	}

	printf("一共转换了%d条指令\n", stat_count);

	//这里只能将opcode写入内存才能生效
	SIZE_T temp;
	WriteProcessMemory(hprocess, (LPVOID)address, opcode, nOpcodeSize, &temp);

	int a = 10;

	// 释放空间
	ks_free(opcode);

	// 关闭句柄
	ks_close(pengine);

}
void dbg::printModules(){//打印模块
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
//隐藏EPB
void dbg::hidePEB()
{
	//过掉反调试

	//进程的基本信息
	DWORD dwRead;
	PROCESS_BASIC_INFORMATION base;
	NtQueryInformationProcess(hprocess,
		ProcessBasicInformation,
		&base,
		sizeof(base),
		&dwRead);

	//读取目标进程PEB
	PEB peb = { 0 };
	ReadProcessMemory(hprocess,
		base.PebBaseAddress,
		&peb,
		sizeof(peb), &dwRead);
	//修改PEB,写回进程
	peb.BeingDebugged = 0;
	WriteProcessMemory(hprocess,
		base.PebBaseAddress,
		&peb,
		sizeof(peb), &dwRead);
}
void dbg::hook(){


	// 2. 获取目标进程的句柄
	
	char IatHookDllName[111] = "C:\\Users\\Rongan Guo\\Documents\\Visual Studio 2013\\Projects\\ConsoleApplication24\\Debug\\ConsoleApplication24.dll";
	// 3. 在目标进程内申请一块空间[作为LoadLibrary的参数]
	LPVOID Buffer = VirtualAllocEx(hprocess, NULL, 0x100,
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// 4. 向空间内写入数据[dll名字]
	SIZE_T RealWrite = 0;

	WriteProcessMemory(hprocess, Buffer, IatHookDllName, strlen(IatHookDllName) + 1, &RealWrite);

	// 5. 创建远程线程, 关键函数 LoadLibrary
	//    注意: 参数的字符类型和 LoadLibrary 的类型需要保持一致
	HANDLE Thread = CreateRemoteThread(hprocess, NULL, NULL,
		(LPTHREAD_START_ROUTINE)LoadLibraryA, Buffer, NULL, NULL);

}
void dbg::extensions(){//检查插件有几个，如果选中就拿到
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

	//遍历当前目录下 plugin 下的dll
	//HMODULE mod = LoadLibrary(L"C:\\Users\\Rongan Guo\\Documents\\Visual Studio 2013\\Projects\\ConsoleApplication24\\Debug\\ConsoleApplication24.dll");

	HANDLE hfile = FindFirstFile(L"C:\\Users\\Rongan Guo\\Documents\\Visual Studio 2013\\Projects\\debugger\\plugin\\*", &wd);
	do
	{
		//过滤特殊文件夹
		if (wcscmp(wd.cFileName, L".") == 0 || wcscmp(wd.cFileName, L"..") == 0)
		{
			continue;
		}

		//尝试加载dll
		wsprintf(dllPath, L"C:\\Users\\Rongan Guo\\Documents\\Visual Studio 2013\\Projects\\debugger\\plugin\\%s", wd.cFileName);
		HMODULE mod = LoadLibrary(dllPath);
		//HMODULE mod = LoadLibrary(L"C:\\Users\\Rongan Guo\\Documents\\Visual Studio 2013\\Projects\\ConsoleApplication24\\Debug\\ConsoleApplication24.dll");

		if (mod == NULL)
		{
			continue;
		}
		//获取dll导出的函数地址
		outp pobj = (outp)GetProcAddress(mod, "returnExtensions");
		//保存插件对象
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
		//3.读取原始数据
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
	//3.读取原始数据
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
		//循环PIMAGE_IMPORT_DESCRIPTOR
		auto INT = (PIMAGE_THUNK_DATA32)(import->OriginalFirstThunk + (DWORD)entry);
		while (INT->u1.Ordinal){
			//循环INT
			if (INT->u1.Ordinal & 0x8000000){
				//首位为1
				printf("%x", INT->u1.Ordinal & 0xFFFF);
			}
			else
			{
				//名称导出
				auto nameStruct = (PIMAGE_IMPORT_BY_NAME)( INT->u1.Ordinal + (DWORD)entry);
				printf("%x,%s\n", nameStruct->Hint, nameStruct->Name);
			}
			INT++;
		}
		import++;
	}
}