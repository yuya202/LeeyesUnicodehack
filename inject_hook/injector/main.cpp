// simple_example.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <../NInjectLib/Process.h>
#include <ShlObj.h>



#pragma comment(linker, "/subsystem:\"windows\" /entry:\"wmainCRTStartup\"")

// Diagnostic launcher log. This is intentionally separate from the injected DLL's
// log so launcher failures can be distinguished from a DLL that never loaded.
static void WriteLauncherDiagnostic(const TCHAR* stage, DWORD errorCode = 0)
{
	TCHAR logPath[MAX_PATH] = {};
	DWORD n = ::GetModuleFileName(NULL, logPath, _countof(logPath));
	if( n == 0 || n >= _countof(logPath) ) return;
	TCHAR* slash = _tcsrchr(logPath, TEXT('\\'));
	if( !slash ) slash = _tcsrchr(logPath, TEXT('/'));
	if( !slash ) return;
	_tcscpy_s(slash + 1, _countof(logPath) - (size_t)(slash + 1 - logPath), TEXT("_injector_debug.txt"));
	FILE* f = nullptr;
	if( _tfopen_s(&f, logPath, TEXT("a")) != 0 || !f ) return;
	_ftprintf(f, TEXT("stage=%s error=%lu\n"), stage ? stage : TEXT("unknown"), errorCode);
	fclose(f);
}

// TargetID: �v���Z�XID
// �߂�l: ���� �]�݂�HWND / ���s NULL
bool IsBackgroundLaunch()
{
	_TCHAR value[8] = {};
	DWORD length = GetEnvironmentVariable(TEXT("LEYEESW_BACKGROUND"), value, _countof(value));
	return length == 1 && value[0] == TEXT('1');
}

struct WindowSearchContext
{
	DWORD processId;
	bool includeHidden;
	HWND result;
};

BOOL CALLBACK FindMainFormWindow(HWND hWnd, LPARAM parameter)
{
	WindowSearchContext* context = reinterpret_cast<WindowSearchContext*>(parameter);
	DWORD processId = 0;
	GetWindowThreadProcessId(hWnd, &processId);
	if( processId != context->processId
		|| (!context->includeHidden && !IsWindowVisible(hWnd)) ) return TRUE;
	TCHAR className[256] = {};
	GetClassName(hWnd, className, _countof(className));
	if( _tcscmp(className, TEXT("TMainForm")) == 0 )
	{
		context->result = hWnd;
		return FALSE;
	}
	return TRUE;
}

HWND GetWindowHandle(	const DWORD TargetID)	
{
	WindowSearchContext context = { TargetID, IsBackgroundLaunch(), NULL };
	EnumWindows(FindMainFormWindow, reinterpret_cast<LPARAM>(&context));
	return context.result;
}

static const TCHAR* gLauncherStage = TEXT("startup");

static void SetLauncherStage(const TCHAR* stage)
{
	gLauncherStage = stage ? stage : TEXT("unknown");
	WriteLauncherDiagnostic(gLauncherStage);
}

static void WriteLauncherException(const TCHAR* stage, const char* message)
{
	WriteLauncherDiagnostic(stage);
	TCHAR logPath[MAX_PATH] = {};
	DWORD n = ::GetModuleFileName(NULL, logPath, _countof(logPath));
	if( n == 0 || n >= _countof(logPath) ) return;
	TCHAR* slash = _tcsrchr(logPath, TEXT('\\'));
	if( !slash ) slash = _tcsrchr(logPath, TEXT('/'));
	if( !slash ) return;
	_tcscpy_s(slash + 1, _countof(logPath) - (size_t)(slash + 1 - logPath), TEXT("_injector_debug.txt"));
	FILE* f = nullptr;
	if( _tfopen_s(&f, logPath, TEXT("a")) != 0 || !f ) return;
	_ftprintf(f, TEXT("exception_stage=%s\nexception_message=%hs\n"), stage, message ? message : "(null)");
	fclose(f);
}

static void AppendDword(std::vector<BYTE>& code, DWORD value)
{
	for( unsigned int shift = 0; shift < 32; shift += 8 )
		code.push_back(static_cast<BYTE>((value >> shift) & 0xFF));
}

static void AppendPushImmediate(std::vector<BYTE>& code, DWORD value)
{
	code.push_back(0x68);
	AppendDword(code, value);
}

struct RemoteListEntry32 { DWORD flink; DWORD blink; };
struct RemoteUnicodeString32 { USHORT length; USHORT maximumLength; DWORD buffer; };
struct RemoteAnsiString32 { USHORT length; USHORT maximumLength; DWORD buffer; };

static LPVOID GetRemoteAddressForLocalFunction(Process& process, HANDLE primaryThread, FARPROC localFunction)
{
	SetLauncherStage(TEXT("resolve_api_local_owner"));
	if( !localFunction ) throw std::exception("Local ntdll API address is null");
	HMODULE localOwner = nullptr;
	SetLauncherStage(TEXT("resolve_api_get_local_module"));
	if( !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		reinterpret_cast<LPCWSTR>(localFunction), &localOwner) )
		throw std::exception("GetModuleHandleExW failed for ntdll API");
	WCHAR modulePath[MAX_PATH] = {};
	if( !GetModuleFileNameW(localOwner, modulePath, _countof(modulePath)) )
		throw std::exception("GetModuleFileNameW failed for ntdll API");
	const WCHAR* moduleName = wcsrchr(modulePath, L'\\');
	moduleName = moduleName ? moduleName + 1 : modulePath;
	if( _wcsicmp(moduleName, L"ntdll.dll") != 0 )
		throw std::exception("Resolved loader API is not owned by ntdll.dll");

	CONTEXT context = {};
	context.ContextFlags = CONTEXT_SEGMENTS;
	SetLauncherStage(TEXT("resolve_api_get_thread_context"));
	if( !GetThreadContext(primaryThread, &context) )
		throw std::exception("GetThreadContext failed while resolving remote ntdll");
	LDT_ENTRY fsEntry = {};
	SetLauncherStage(TEXT("resolve_api_get_fs_selector"));
	if( !GetThreadSelectorEntry(primaryThread, context.SegFs, &fsEntry) )
		throw std::exception("GetThreadSelectorEntry failed while resolving remote ntdll");
	DWORD fsBase = (static_cast<DWORD>(fsEntry.HighWord.Bytes.BaseHi) << 24)
		| (static_cast<DWORD>(fsEntry.HighWord.Bytes.BaseMid) << 16) | fsEntry.BaseLow;
	DWORD peb = 0;
	SetLauncherStage(TEXT("resolve_api_read_peb_pointer"));
	process.readMemory(reinterpret_cast<LPVOID>(fsBase + 0x30), &peb, sizeof(peb));
	DWORD ldr = 0;
	SetLauncherStage(TEXT("resolve_api_read_peb_ldr"));
	process.readMemory(reinterpret_cast<LPVOID>(peb + 0x0C), &ldr, sizeof(ldr));
	if( !ldr ) throw std::exception("Remote PEB loader data is not initialized");

	SetLauncherStage(TEXT("resolve_api_read_loader_list"));
	const DWORD listHead = ldr + 0x14;
	RemoteListEntry32 head = {};
	process.readMemory(reinterpret_cast<LPVOID>(listHead), &head, sizeof(head));
	DWORD link = head.flink;
	for( unsigned int count = 0; link && link != listHead && count < 256; ++count )
	{
		const DWORD entry = link - 0x08;
		DWORD remoteBase = 0;
		process.readMemory(reinterpret_cast<LPVOID>(entry + 0x18), &remoteBase, sizeof(remoteBase));
		RemoteUnicodeString32 baseName = {};
		process.readMemory(reinterpret_cast<LPVOID>(entry + 0x2C), &baseName, sizeof(baseName));
		if( remoteBase && baseName.buffer && baseName.length >= sizeof(WCHAR)
			&& baseName.length <= MAX_PATH * sizeof(WCHAR) )
		{
			std::vector<WCHAR> name(baseName.length / sizeof(WCHAR) + 1, L'\0');
			process.readMemory(reinterpret_cast<LPVOID>(baseName.buffer), name.data(), baseName.length);
			if( _wcsicmp(name.data(), L"ntdll.dll") == 0 )
			{
				const uintptr_t rva = reinterpret_cast<uintptr_t>(localFunction) - reinterpret_cast<uintptr_t>(localOwner);
				WriteLauncherDiagnostic(TEXT("remote_ntdll_module_found"), remoteBase);
				return reinterpret_cast<LPVOID>(static_cast<uintptr_t>(remoteBase) + rva);
			}
		}
		RemoteListEntry32 current = {};
		process.readMemory(reinterpret_cast<LPVOID>(link), &current, sizeof(current));
		link = current.flink;
	}
	throw std::exception("Could not locate ntdll.dll in Leeyes PEB loader list");
}

struct RemoteBootstrapStatus
{
	DWORD stage;
	DWORD loadLibraryStatus;
	DWORD loadedModule;
	DWORD getProcAddressStatus;
	DWORD initializerAddress;
};

static LPVOID CreatePreEntryBootstrap(Process& process, LPVOID remoteStatus,
	LPVOID remoteDllName, LPVOID remoteDllHandle, LPVOID remoteInitAnsi,
	LPVOID remoteInitAddress, DWORD resumeAddress, LPVOID ldrLoadDll, LPVOID ldrGetProcedureAddress)
{
	std::vector<BYTE> code;
	auto movEdx = [&](DWORD value) { code.push_back(0xBA); AppendDword(code, value); };
	auto storeStage = [&](DWORD value) {
		movEdx(static_cast<DWORD>(reinterpret_cast<uintptr_t>(remoteStatus)));
		code.push_back(0xC7); code.push_back(0x02); AppendDword(code, value);
	};
	auto storeEax = [&](BYTE offset) {
		movEdx(static_cast<DWORD>(reinterpret_cast<uintptr_t>(remoteStatus)));
		code.push_back(0x89); code.push_back(0x42); code.push_back(offset);
	};
	auto appendResume = [&]() {
		code.push_back(0x61); code.push_back(0x9D);
		AppendPushImmediate(code, resumeAddress); code.push_back(0xC3);
	};

	code.push_back(0x9C); code.push_back(0x60);
	storeStage(1);
	// LdrLoadDll(NULL, NULL, &DllName, &DllHandle)
	AppendPushImmediate(code, static_cast<DWORD>(reinterpret_cast<uintptr_t>(remoteDllHandle)));
	AppendPushImmediate(code, static_cast<DWORD>(reinterpret_cast<uintptr_t>(remoteDllName)));
	AppendPushImmediate(code, 0); AppendPushImmediate(code, 0);
	code.push_back(0xB8); AppendDword(code, static_cast<DWORD>(reinterpret_cast<uintptr_t>(ldrLoadDll)));
	code.push_back(0xFF); code.push_back(0xD0);
	storeEax(4);
	code.push_back(0x85); code.push_back(0xC0);
	code.push_back(0x78); size_t loadFail = code.size(); code.push_back(0);
	movEdx(static_cast<DWORD>(reinterpret_cast<uintptr_t>(remoteDllHandle)));
	code.push_back(0x8B); code.push_back(0x02); storeEax(8);
	code.push_back(0x85); code.push_back(0xC0);
	code.push_back(0x74); size_t moduleNull = code.size(); code.push_back(0);

	// LdrGetProcedureAddress(DllHandle, &Name, 0, &ProcedureAddress)
	AppendPushImmediate(code, static_cast<DWORD>(reinterpret_cast<uintptr_t>(remoteInitAddress)));
	AppendPushImmediate(code, 0);
	AppendPushImmediate(code, static_cast<DWORD>(reinterpret_cast<uintptr_t>(remoteInitAnsi)));
	movEdx(static_cast<DWORD>(reinterpret_cast<uintptr_t>(remoteDllHandle)));
	code.push_back(0xFF); code.push_back(0x32);
	code.push_back(0xB8); AppendDword(code, static_cast<DWORD>(reinterpret_cast<uintptr_t>(ldrGetProcedureAddress)));
	code.push_back(0xFF); code.push_back(0xD0);
	storeEax(12);
	code.push_back(0x85); code.push_back(0xC0);
	code.push_back(0x78); size_t procFail = code.size(); code.push_back(0);
	movEdx(static_cast<DWORD>(reinterpret_cast<uintptr_t>(remoteInitAddress)));
	code.push_back(0x8B); code.push_back(0x02); storeEax(16);
	code.push_back(0x85); code.push_back(0xC0);
	code.push_back(0x74); size_t procNull = code.size(); code.push_back(0);
	storeStage(3);
	code.push_back(0xFF); code.push_back(0xD0);
	storeStage(4);
	code.push_back(0xE9); size_t okJump = code.size(); AppendDword(code, 0);

	size_t loadFailLabel = code.size(); storeStage(0xE1);
	code.push_back(0xE9); size_t loadFailRel = code.size(); AppendDword(code, 0);
	size_t moduleNullLabel = code.size(); storeStage(0xE3);
	code.push_back(0xE9); size_t moduleNullRel = code.size(); AppendDword(code, 0);
	size_t procFailLabel = code.size(); storeStage(0xE2);
	code.push_back(0xE9); size_t procFailRel = code.size(); AppendDword(code, 0);
	size_t procNullLabel = code.size(); storeStage(0xE4);
	code.push_back(0xE9); size_t procNullRel = code.size(); AppendDword(code, 0);
	size_t resumeLabel = code.size(); appendResume();

	auto patch8 = [&](size_t at, size_t to) {
		int d = static_cast<int>(to) - static_cast<int>(at + 1);
		if( d < -128 || d > 127 ) throw std::exception("bootstrap short jump out of range");
		code[at] = static_cast<BYTE>(static_cast<signed char>(d));
	};
	auto patch32 = [&](size_t at, size_t to) {
		int32_t d = static_cast<int32_t>(to) - static_cast<int32_t>(at + 4);
		for( unsigned int i = 0; i < 4; ++i ) code[at+i] = static_cast<BYTE>((static_cast<uint32_t>(d) >> (i*8)) & 0xFF);
	};
	patch8(loadFail, loadFailLabel); patch8(moduleNull, moduleNullLabel);
	patch8(procFail, procFailLabel); patch8(procNull, procNullLabel);
	patch32(okJump, resumeLabel); patch32(loadFailRel, resumeLabel);
	patch32(moduleNullRel, resumeLabel); patch32(procFailRel, resumeLabel); patch32(procNullRel, resumeLabel);
	LPVOID remoteCode = process.allocMem(static_cast<DWORD>(code.size()));
	process.writeMemory(remoteCode, code.data(), static_cast<DWORD>(code.size()));
	return remoteCode;
}

// The initial system breakpoint is delivered after Windows initializes PEB.Ldr
// and before the target EXE reaches its entry point.
static void CloseDebugEventHandles(const DEBUG_EVENT& event)
{
	switch( event.dwDebugEventCode )
	{
	case CREATE_PROCESS_DEBUG_EVENT:
		if( event.u.CreateProcessInfo.hFile ) CloseHandle(event.u.CreateProcessInfo.hFile);
		if( event.u.CreateProcessInfo.hThread ) CloseHandle(event.u.CreateProcessInfo.hThread);
		if( event.u.CreateProcessInfo.hProcess ) CloseHandle(event.u.CreateProcessInfo.hProcess);
		break;
	case CREATE_THREAD_DEBUG_EVENT:
		if( event.u.CreateThread.hThread ) CloseHandle(event.u.CreateThread.hThread);
		break;
	case LOAD_DLL_DEBUG_EVENT:
		if( event.u.LoadDll.hFile ) CloseHandle(event.u.LoadDll.hFile);
		break;
	default:
		break;
	}
}

static void ContinueDebugEventChecked(const DEBUG_EVENT& event, DWORD disposition)
{
	if( !ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition) )
	{
		DWORD error = GetLastError();
		std::ostringstream message;
		message << "ContinueDebugEvent failed: " << error;
		throw std::runtime_error(message.str());
	}
}

static DEBUG_EVENT WaitForInitialSystemBreakpoint(const PROCESS_INFORMATION& processInfo)
{
	const ULONGLONG started = GetTickCount64();
	for(;;)
	{
		DEBUG_EVENT event = {};
		if( !WaitForDebugEvent(&event, 1000) )
		{
			DWORD error = GetLastError();
			if( error == ERROR_SEM_TIMEOUT )
			{
				if( GetTickCount64() - started >= 30000 )
					throw std::runtime_error("Timed out waiting for the initial Windows debugger breakpoint");
				continue;
			}
			std::ostringstream message;
			message << "WaitForDebugEvent failed: " << error;
			throw std::runtime_error(message.str());
		}
		if( event.dwProcessId == processInfo.dwProcessId
			&& event.dwThreadId == processInfo.dwThreadId
			&& event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
			&& event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT )
		{
			WriteLauncherDiagnostic(TEXT("initial_system_breakpoint_received"));
			return event;
		}
		DWORD disposition = event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
			? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
		const bool exited = event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT;
		CloseDebugEventHandles(event);
		ContinueDebugEventChecked(event, disposition);
		if( exited ) throw std::runtime_error("Leeyes exited before the initial system breakpoint");
	}
}

static RemoteBootstrapStatus WaitForBootstrapWithDebugEvents(
	const PROCESS_INFORMATION& processInfo, Process& process, LPVOID remoteStatus)
{
	const ULONGLONG started = GetTickCount64();
	RemoteBootstrapStatus status = {};
	for(;;)
	{
		process.readMemory(remoteStatus, &status, sizeof(status));
		if( status.stage == 4 || status.stage >= 0xE0 ) return status;
		if( GetTickCount64() - started >= 30000 )
			throw std::runtime_error("DLL bootstrap did not report completion within 30 seconds");
		DEBUG_EVENT event = {};
		if( !WaitForDebugEvent(&event, 50) )
		{
			DWORD error = GetLastError();
			if( error == ERROR_SEM_TIMEOUT ) continue;
			std::ostringstream message;
			message << "WaitForDebugEvent failed during DLL bootstrap: " << error;
			throw std::runtime_error(message.str());
		}
		const bool exited = event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT;
		DWORD disposition = event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
			? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
		CloseDebugEventHandles(event);
		ContinueDebugEventChecked(event, disposition);
		if( exited ) throw std::runtime_error("Leeyes exited during DLL bootstrap");
	}
}


int _tmain(int argc, _TCHAR* argv[])
{
	WriteLauncherDiagnostic(TEXT("launcher_start"));
	/*if (argc != 3)
	{
		std::cout << "Usage is: simple_example executable dll" << std::endl;
		return 1;
	}*/

	//const char* exe = argv[1];
	//const char* dll = argv[2];

	LPCTSTR exe = TEXT("Leeyes.exe");
	LPCTSTR dll = TEXT("inject_dll.dll");
	bool backgroundLaunch = IsBackgroundLaunch();

	TCHAR path[MAX_PATH]={};
	TCHAR current_dir[MAX_PATH]={};
	TCHAR dllFullPath[MAX_PATH]={};

	_tcscpy_s( path, argv[0] );
	auto find = _tcsrchr( path, TEXT('\\'));
	if( find && find < (path+MAX_PATH-2) )
	{
		find = _tcsinc(find);
		*find =  TEXT('\0');
		_tcscpy_s( current_dir, path );
		if(_tcscat_s( path,MAX_PATH,  exe))
		{
			abort();
		}
		_tcscpy_s( dllFullPath, current_dir );
		if(_tcscat_s( dllFullPath, MAX_PATH, dll))
		{
			abort();
		}
	}
	else
	{
		abort();
	}

	STARTUPINFO sInfo = {0};
	sInfo.cb = sizeof(STARTUPINFO);
	HWND previousForeground = backgroundLaunch ? ::GetForegroundWindow() : NULL;
	if( backgroundLaunch )
	{
		// Keep the diagnostic target minimized without activation.  The original
		// foreground window is restored after Leeyes' startup settles so the
		// minimized target cannot take the user's focus.
		sInfo.dwFlags |= STARTF_USESHOWWINDOW;
		sInfo.wShowWindow = SW_SHOWMINNOACTIVE;
	}
	PROCESS_INFORMATION pInfo= {0};
	LPTSTR option = argv[1];

	if (CreateProcess(path, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, current_dir, &sInfo, &pInfo))
	{
		WriteLauncherDiagnostic(TEXT("create_process_ok"));
		bool initialBreakpointPending = false;
		try
		{
			SetLauncherStage(TEXT("wait_for_initial_system_breakpoint"));
			if( !DebugSetProcessKillOnExit(FALSE) )
				throw std::runtime_error("DebugSetProcessKillOnExit failed");
			DEBUG_EVENT initialBreakpoint = WaitForInitialSystemBreakpoint(pInfo);
			initialBreakpointPending = true;
			SetLauncherStage(TEXT("open_target_process"));
			Process process(pInfo.dwProcessId);

			SetLauncherStage(TEXT("allocate_remote_arguments"));
			DWORD dllPathSize = (_tcslen(dllFullPath) + 1) * sizeof(TCHAR);
			LPVOID remoteDllPath = process.allocMem(dllPathSize);
			process.writeMemory(remoteDllPath, dllFullPath, dllPathSize);
			RemoteUnicodeString32 dllName = {};
			dllName.length = static_cast<USHORT>(dllPathSize - sizeof(TCHAR));
			dllName.maximumLength = static_cast<USHORT>(dllPathSize);
			dllName.buffer = static_cast<DWORD>(reinterpret_cast<uintptr_t>(remoteDllPath));
			LPVOID remoteDllName = process.allocMem(sizeof(dllName));
			process.writeMemory(remoteDllName, &dllName, sizeof(dllName));
			DWORD moduleValue = 0;
			LPVOID remoteDllHandle = process.allocMem(sizeof(moduleValue));
			process.writeMemory(remoteDllHandle, &moduleValue, sizeof(moduleValue));

			static const char initName[] = "InitializeLeeyesInternalHooks";
			LPVOID remoteInitName = process.allocMem(sizeof(initName));
			process.writeMemory(remoteInitName, initName, sizeof(initName));
			RemoteAnsiString32 initAnsi = {};
			initAnsi.length = static_cast<USHORT>(sizeof(initName) - 1);
			initAnsi.maximumLength = static_cast<USHORT>(sizeof(initName));
			initAnsi.buffer = static_cast<DWORD>(reinterpret_cast<uintptr_t>(remoteInitName));
			LPVOID remoteInitAnsi = process.allocMem(sizeof(initAnsi));
			process.writeMemory(remoteInitAnsi, &initAnsi, sizeof(initAnsi));
			DWORD initAddressValue = 0;
			LPVOID remoteInitAddress = process.allocMem(sizeof(initAddressValue));
			process.writeMemory(remoteInitAddress, &initAddressValue, sizeof(initAddressValue));
			RemoteBootstrapStatus initialStatus = {};
			LPVOID remoteStatus = process.allocMem(sizeof(initialStatus));
			process.writeMemory(remoteStatus, &initialStatus, sizeof(initialStatus));

			SetLauncherStage(TEXT("resolve_local_ntdll_loader_apis"));
			HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
			FARPROC localLdrLoadDll = GetProcAddress(hNtdll, "LdrLoadDll");
			FARPROC localLdrGetProcedureAddress = GetProcAddress(hNtdll, "LdrGetProcedureAddress");
			if( !localLdrLoadDll || !localLdrGetProcedureAddress )
				throw std::exception("Could not resolve local ntdll loader APIs");
			SetLauncherStage(TEXT("resolve_remote_ldrloaddll"));
			LPVOID pLdrLoadDll = GetRemoteAddressForLocalFunction(process, pInfo.hThread, localLdrLoadDll);
			SetLauncherStage(TEXT("resolve_remote_ldrgetprocedureaddress"));
			LPVOID pLdrGetProcedureAddress = GetRemoteAddressForLocalFunction(process, pInfo.hThread, localLdrGetProcedureAddress);
			// Redirect the still-suspended primary thread through LoadLibraryW before it
			// reaches Leeyes' real entry point, so every hook - including the Susie image
			// plugin ones - is installed before Leeyes does its own early plugin-scanning
			// startup work (which resolves GetProcAddress for image plugins too early for a
			// post-startup injection to catch). This technique was previously abandoned
			// because it matched a "suspended process injection" pattern that triggered a
			// crash via a p9np.dll bug on this system; that root cause is now fixed
			// independently (inject_dll.dll blocks p9np.dll's own load and hides P9NP from
			// this process's view of the network provider list), so this ordering is safe
			// again and lets hooks cover Leeyes' full startup sequence.
			// The initial system breakpoint occurs after ntdll initialized PEB.Ldr
			// and before Leeyes reaches its EXE entry point.
			SetLauncherStage(TEXT("read_initial_breakpoint_context"));
			CONTEXT ctx = {};
			ctx.ContextFlags = CONTEXT_CONTROL;
			if( !GetThreadContext(pInfo.hThread, &ctx) )
				throw std::runtime_error("GetThreadContext failed at the initial system breakpoint");
			DWORD resumeAddress = ctx.Eip;
			const DWORD exceptionAddress = reinterpret_cast<DWORD>(
				initialBreakpoint.u.Exception.ExceptionRecord.ExceptionAddress);
			if( resumeAddress == exceptionAddress )
			{
				BYTE opcode = 0;
				process.readMemory(reinterpret_cast<LPVOID>(exceptionAddress), &opcode, sizeof(opcode));
				if( opcode != 0xCC )
					throw std::runtime_error("Initial breakpoint EIP is ambiguous; refusing to alter startup context");
				++resumeAddress;
			}
			else if( resumeAddress != exceptionAddress + 1 )
				throw std::runtime_error("Initial breakpoint EIP does not match the expected x86 INT3 instruction");
			WriteLauncherDiagnostic(TEXT("initial_breakpoint_resume_eip"), resumeAddress);

			SetLauncherStage(TEXT("install_initial_breakpoint_bootstrap"));
			ctx.Eip = reinterpret_cast<DWORD>(CreatePreEntryBootstrap(
				process, remoteStatus, remoteDllName, remoteDllHandle, remoteInitAnsi,
				remoteInitAddress, resumeAddress, pLdrLoadDll, pLdrGetProcedureAddress));
			if( !SetThreadContext(pInfo.hThread, &ctx) )
				throw std::runtime_error("SetThreadContext failed while installing initial-breakpoint bootstrap");
			WriteLauncherDiagnostic(TEXT("bootstrap_installed"));

			SetLauncherStage(TEXT("continue_initial_breakpoint"));
			ContinueDebugEventChecked(initialBreakpoint, DBG_CONTINUE);
			initialBreakpointPending = false;

			SetLauncherStage(TEXT("wait_for_dll_bootstrap_with_debug_events"));
			RemoteBootstrapStatus bootstrapStatus =
				WaitForBootstrapWithDebugEvents(pInfo, process, remoteStatus);

			// Record the remote loader result BEFORE attempting to detach the debugger.
			// DebugActiveProcessStop can fail independently (for example, ERROR_ACCESS_DENIED);
			// that must never hide whether LdrLoadDll or the exported initializer actually ran.
			WriteLauncherDiagnostic(TEXT("dll_bootstrap_stage"), bootstrapStatus.stage);
			WriteLauncherDiagnostic(TEXT("dll_ldrloaddll_status"), bootstrapStatus.loadLibraryStatus);
			WriteLauncherDiagnostic(TEXT("dll_loaded_module"), bootstrapStatus.loadedModule);
			WriteLauncherDiagnostic(TEXT("dll_ldrgetprocedureaddress_status"), bootstrapStatus.getProcAddressStatus);
			WriteLauncherDiagnostic(TEXT("dll_initializer_export"), bootstrapStatus.initializerAddress);
			WriteLauncherDiagnostic(
				bootstrapStatus.stage == 4 ? TEXT("dll_initializer_completed") :
				TEXT("dll_bootstrap_failed"),
				bootstrapStatus.stage);

			if( !DebugActiveProcessStop(pInfo.dwProcessId) )
			{
				DWORD error = GetLastError();
				WriteLauncherDiagnostic(TEXT("debugger_detach_failed"), error);
				std::ostringstream message;
				message << "DebugActiveProcessStop failed: " << error
					<< "; remote bootstrap stage=" << bootstrapStatus.stage;
				throw std::runtime_error(message.str());
			}
			WriteLauncherDiagnostic(TEXT("debugger_detached"));
			if( bootstrapStatus.stage != 4 )
				throw std::exception("DLL load or internal-hook initializer failed");

			if( option )
			{
				DWORD idleResult = WaitForInputIdle( pInfo.hProcess, 5000 );
				WriteLauncherDiagnostic(TEXT("wait_for_input_idle_returned"), idleResult);
				if( idleResult != 0 && idleResult != WAIT_TIMEOUT )
				{
					throw std::exception("WaitForInputIdle failed");
				}
				
				HWND hwnd = NULL;
				TCHAR windowTitle[256] = {};
				TCHAR windowClass[256] = {};
				// A large folder can keep Leeyes in its startup/list-building phase for
				// longer than the old 20-second polling limit.  Do not turn that normal
				// startup delay into a false injection failure.  The process handle is
				// checked on every pass so a real early exit still fails promptly.
				const ULONGLONG windowWaitStarted = GetTickCount64();
				const ULONGLONG windowWaitLimit = 120000;
				for(;;)
				{
					hwnd = GetWindowHandle( pInfo.dwProcessId);
					if( hwnd )
					{
						GetWindowText(hwnd, windowTitle, _countof(windowTitle));
						// The diagnostic path includes hidden windows and only needs a
						// stable HWND for WM_DROPFILES; the normal path retains the title
						// check used by the original launcher.
						if( backgroundLaunch || windowTitle[0] != TEXT('\0') ) break;
					}
					if( WaitForSingleObject(pInfo.hProcess, 0) == WAIT_OBJECT_0 )
					{
						throw std::exception("Leeyes exited before TMainForm was created");
					}
					if( GetTickCount64() - windowWaitStarted >= windowWaitLimit )
					{
						throw std::exception("TMainForm wait timed out after 120 seconds");
					}
					Sleep(20);
				}
				// TMainForm recreates its HWND while restoring startup state.  A handle
				// discovered at the first visible/title-bearing moment can therefore be
				// invalid before WM_DROPFILES reaches the queue.  Require the same live
				// main-form handle to survive for half a second.
				HWND stableHwnd = hwnd;
				DWORD stableCount = 0;
				DWORD stabilityWait = 0;
				while( stableCount < 25 )
				{
					if( stabilityWait++ > 500 )
						throw std::exception("TMainForm did not stabilize");
					Sleep(20);
					HWND candidate = GetWindowHandle( pInfo.dwProcessId );
					if( candidate && candidate == stableHwnd && IsWindow(candidate) )
						++stableCount;
					else
					{
						stableHwnd = candidate;
						stableCount = 0;
					}
				}
				hwnd = stableHwnd;
				if( backgroundLaunch && previousForeground && ::IsWindow(previousForeground) )
					::SetForegroundWindow(previousForeground);
				GetClassName(hwnd, windowClass, _countof(windowClass));
				#ifdef UNICODE
				std::wcout << L"DROP_TARGET hwnd=" << hwnd << L" title=[" << windowTitle << L"] class=[" << windowClass << L"]" << std::endl;
				#else
				std::cout << "DROP_TARGET hwnd=" << hwnd << " title=[" << windowTitle << "] class=[" << windowClass << "]" << std::endl;
				#endif
				LPDROPFILES dropfiles = nullptr;
				auto length = _tcslen( option );
				// Leeyes imports DragQueryFileA, but its drop handler needs the
				// original Unicode HDROP so the A/W hook pair can recover a CP932
				// collision such as U+00B7/U+30FB without losing the source path.
				// The injector is a Unicode build, so an ANSI HDROP is never needed.
				DWORD payloadBytes = (DWORD)((length + 2) * sizeof(TCHAR));
				DWORD size = sizeof(DROPFILES) + payloadBytes;
				HGLOBAL h = ::GlobalAlloc( GMEM_MOVEABLE | GMEM_ZEROINIT, size );
				if( !h ) throw std::exception("GlobalAlloc for HDROP failed");
				dropfiles = (LPDROPFILES)::GlobalLock( h );
				if( !dropfiles )
				{
					::GlobalFree( h );
					throw std::exception("GlobalLock for HDROP failed");
				}

				dropfiles->fWide = TRUE;
				dropfiles->fNC = FALSE;
				dropfiles->pFiles = sizeof(DROPFILES);
				dropfiles->pt = POINT();
				LPTSTR filenamelist = reinterpret_cast<LPTSTR>(
					reinterpret_cast<LPBYTE>(dropfiles) + sizeof(DROPFILES));
				if( _tcscpy_s(filenamelist, length + 2, option) )
				{
					::GlobalUnlock( h );
					::GlobalFree( h );
					throw std::exception("Cant Write File Name");
				}
				// DROPFILES lists are terminated by two null TCHARs.
				filenamelist[length + 1] = TEXT('\0');
				::GlobalUnlock( h );
				BOOL sendResult = ::PostMessage(hwnd, WM_DROPFILES, WPARAM(h), 0);
				std::cout << "WM_DROPFILES_POST_RESULT=" << sendResult
					<< " LAST_ERROR=" << GetLastError() << std::endl;
				if( !sendResult )
				{
					// Ownership transfers to the receiver only when PostMessage
					// succeeds. On failure the injector must release the HDROP.
					::GlobalFree( h );
					throw std::exception("WM_DROPFILES PostMessage failed");
				}
			}
			std::cout << "DLL successfully injected" << std::endl;
			WriteLauncherDiagnostic(TEXT("launcher_completed"));
		}
		catch (std::exception& e)
		{
			WriteLauncherException(gLauncherStage, e.what());
			std::cout << "Error while trying to inject dll into process: " << e.what() << std::endl;
			if( initialBreakpointPending )
			{
				ContinueDebugEvent(pInfo.dwProcessId, pInfo.dwThreadId, DBG_CONTINUE);
				initialBreakpointPending = false;
			}
			DebugActiveProcessStop(pInfo.dwProcessId);
			CloseHandle(pInfo.hThread);
			CloseHandle(pInfo.hProcess);
		}
	}
	else
	{
		DWORD lastErr = GetLastError();
		WriteLauncherDiagnostic(TEXT("create_process_failed"), lastErr);
		std::cout << "Failed to start process, system error: " << lastErr << std::endl;
	}
	return 0;
}
