// simple_example.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
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

static LPVOID GetRemoteAddressForLocalFunction(Process& process, HANDLE primaryThread,
	FARPROC localFunction)
{
	if( !localFunction ) throw std::exception("Local API address is null");
	HMODULE localOwner = nullptr;
	if( !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
		| GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		reinterpret_cast<LPCWSTR>(localFunction), &localOwner) )
		throw std::exception("GetModuleHandleExW failed for system API");
	WCHAR modulePath[MAX_PATH] = {};
	if( !GetModuleFileNameW(localOwner, modulePath, _countof(modulePath)) )
		throw std::exception("GetModuleFileNameW failed for system API");
	const WCHAR* moduleName = wcsrchr(modulePath, L'\\');
	moduleName = moduleName ? moduleName + 1 : modulePath;

	CONTEXT context = {};
	context.ContextFlags = CONTEXT_SEGMENTS;
	if( !GetThreadContext(primaryThread, &context) )
		throw std::exception("GetThreadContext failed while resolving remote module");
	LDT_ENTRY fsEntry = {};
	if( !GetThreadSelectorEntry(primaryThread, context.SegFs, &fsEntry) )
		throw std::exception("GetThreadSelectorEntry failed while resolving remote module");
	DWORD fsBase = (static_cast<DWORD>(fsEntry.HighWord.Bytes.BaseHi) << 24)
		| (static_cast<DWORD>(fsEntry.HighWord.Bytes.BaseMid) << 16)
		| fsEntry.BaseLow;
	DWORD peb = 0;
	process.readMemory(reinterpret_cast<LPVOID>(fsBase + 0x30), &peb, sizeof(peb));
	DWORD ldr = 0;
	process.readMemory(reinterpret_cast<LPVOID>(peb + 0x0C), &ldr, sizeof(ldr));
	if( !ldr ) throw std::exception("Remote PEB loader data is not initialized");

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
			std::vector<WCHAR> name(baseName.length / sizeof(WCHAR) + 1, L'\\0');
			process.readMemory(reinterpret_cast<LPVOID>(baseName.buffer), name.data(), baseName.length);
			if( _wcsicmp(name.data(), moduleName) == 0 )
			{
				const uintptr_t rva = reinterpret_cast<uintptr_t>(localFunction)
					- reinterpret_cast<uintptr_t>(localOwner);
				return reinterpret_cast<LPVOID>(static_cast<uintptr_t>(remoteBase) + rva);
			}
		}
		RemoteListEntry32 current = {};
		process.readMemory(reinterpret_cast<LPVOID>(link), &current, sizeof(current));
		link = current.flink;
	}
	throw std::exception("Could not locate API owner module in Leeyes PEB loader list");
}

struct RemoteBootstrapStatus
{
	DWORD stage;
	DWORD loadLibraryResult;
	DWORD getProcAddressResult;
};

static LPVOID CreatePreEntryBootstrap(Process& process, LPVOID remoteDllPath,
	LPVOID remoteStatus, LPVOID remoteInitName, DWORD originalEntryPoint,
	LPVOID loadLibrary, LPVOID getProcAddress)
{
	std::vector<BYTE> code;
	auto movEdx = [&](DWORD value)
	{
		code.push_back(0xBA);
		AppendDword(code, value);
	};
	auto storeStage = [&](DWORD value)
	{
		movEdx(static_cast<DWORD>(reinterpret_cast<uintptr_t>(remoteStatus)));
		code.push_back(0xC7); code.push_back(0x02);
		AppendDword(code, value);
	};
	auto jumpToEntry = [&]()
	{
		code.push_back(0xBA);
		AppendDword(code, originalEntryPoint);
		code.push_back(0xFF); code.push_back(0xE2);
	};

	storeStage(1);
	AppendPushImmediate(code, static_cast<DWORD>(reinterpret_cast<uintptr_t>(remoteDllPath)));
	code.push_back(0xB8);
	AppendDword(code, static_cast<DWORD>(reinterpret_cast<uintptr_t>(loadLibrary)));
	code.push_back(0xFF); code.push_back(0xD0);
	movEdx(static_cast<DWORD>(reinterpret_cast<uintptr_t>(remoteStatus)));
	code.push_back(0x89); code.push_back(0x42); code.push_back(0x04);
	storeStage(2);
	code.push_back(0x85); code.push_back(0xC0);
	code.push_back(0x74);
	size_t loadFailedJump = code.size();
	code.push_back(0);

	AppendPushImmediate(code, static_cast<DWORD>(reinterpret_cast<uintptr_t>(remoteInitName)));
	code.push_back(0x50);
	code.push_back(0xB8);
	AppendDword(code, static_cast<DWORD>(reinterpret_cast<uintptr_t>(getProcAddress)));
	code.push_back(0xFF); code.push_back(0xD0);
	movEdx(static_cast<DWORD>(reinterpret_cast<uintptr_t>(remoteStatus)));
	code.push_back(0x89); code.push_back(0x42); code.push_back(0x08);
	code.push_back(0x85); code.push_back(0xC0);
	code.push_back(0x74);
	size_t exportFailedJump = code.size();
	code.push_back(0);

	storeStage(3);
	code.push_back(0xFF); code.push_back(0xD0);
	storeStage(4);
	code.push_back(0xE9);
	size_t successDisplacement = code.size();
	AppendDword(code, 0);

	size_t loadFailed = code.size();
	storeStage(0xE1);
	code.push_back(0xE9);
	size_t loadFailedDisplacement = code.size();
	AppendDword(code, 0);

	size_t exportFailed = code.size();
	storeStage(0xE2);
	code.push_back(0xE9);
	size_t exportFailedDisplacement = code.size();
	AppendDword(code, 0);

	size_t entryJump = code.size();
	jumpToEntry();

	auto patchRel8 = [&](size_t displacement, size_t target)
	{
		int value = static_cast<int>(target) - static_cast<int>(displacement + 1);
		if( value < -128 || value > 127 ) throw std::exception("bootstrap short jump out of range");
		code[displacement] = static_cast<BYTE>(static_cast<signed char>(value));
	};
	auto patchRel32 = [&](size_t displacement, size_t target)
	{
		int32_t value = static_cast<int32_t>(target) - static_cast<int32_t>(displacement + 4);
		for( unsigned int i = 0; i < 4; ++i )
			code[displacement + i] = static_cast<BYTE>((static_cast<uint32_t>(value) >> (i * 8)) & 0xFF);
	};
	patchRel8(loadFailedJump, loadFailed);
	patchRel8(exportFailedJump, exportFailed);
	patchRel32(successDisplacement, entryJump);
	patchRel32(loadFailedDisplacement, entryJump);
	patchRel32(exportFailedDisplacement, entryJump);

	LPVOID remoteCode = process.allocMem(static_cast<DWORD>(code.size()));
	process.writeMemory(remoteCode, code.data(), static_cast<DWORD>(code.size()));
	return remoteCode;
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

	if (CreateProcess(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, current_dir, &sInfo, &pInfo))
	{
		WriteLauncherDiagnostic(TEXT("create_process_ok"));
		try
		{
			Process process(pInfo.dwProcessId);

			DWORD dllPathSize = (_tcslen(dllFullPath) + 1) * sizeof(TCHAR);
			LPVOID remoteDllPath = process.allocMem(dllPathSize);
			process.writeMemory(remoteDllPath, dllFullPath, dllPathSize);
			static const char initName[] = "InitializeLeeyesInternalHooks";
			LPVOID remoteInitName = process.allocMem(sizeof(initName));
			process.writeMemory(remoteInitName, initName, sizeof(initName));
			RemoteBootstrapStatus initialStatus = {};
			LPVOID remoteStatus = process.allocMem(sizeof(initialStatus));
			process.writeMemory(remoteStatus, &initialStatus, sizeof(initialStatus));

			HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
			FARPROC localLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");
			FARPROC localGetProcAddress = GetProcAddress(hKernel32, "GetProcAddress");
			if( !localLoadLibrary || !localGetProcAddress )
				throw std::exception("Could not resolve local Kernel32 loader APIs");
			LPVOID pLoadLibrary = GetRemoteAddressForLocalFunction(
				process, pInfo.hThread, localLoadLibrary);
			LPVOID pGetProcAddress = GetRemoteAddressForLocalFunction(
				process, pInfo.hThread, localGetProcAddress);

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
			uintptr_t imageBase = process.getImageBase(pInfo.hThread);
			IMAGE_DOS_HEADER dosHeader;
			process.readMemory((LPVOID)imageBase, &dosHeader, sizeof(dosHeader));
			IMAGE_NT_HEADERS ntHeaders;
			process.readMemory((LPVOID)(imageBase + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders));
			DWORD originalEntryPoint = (DWORD)(imageBase + ntHeaders.OptionalHeader.AddressOfEntryPoint);

			CONTEXT ctx = {};
			ctx.ContextFlags = CONTEXT_CONTROL;
			if (!GetThreadContext(pInfo.hThread, &ctx)) throw std::exception("GetThreadContext failed");

			// Keep the primary thread suspended while LoadLibraryW returns and the
			// exported internal-hook initializer runs outside loader lock. The stub
			// then jumps to the original entry point without changing its startup stack.
			ctx.Eip = reinterpret_cast<DWORD>(CreatePreEntryBootstrap(
				process, remoteDllPath, remoteStatus, remoteInitName,
				originalEntryPoint, pLoadLibrary, pGetProcAddress));
			if (!SetThreadContext(pInfo.hThread, &ctx)) throw std::exception("SetThreadContext failed");
			WriteLauncherDiagnostic(TEXT("bootstrap_installed"));

			ResumeThread(pInfo.hThread);
			WriteLauncherDiagnostic(TEXT("primary_thread_resumed"));

			// Resuming the primary thread is not proof that LoadLibrary succeeded.
			// Read the bootstrap's explicit status from the target process.
			const ULONGLONG injectionWaitStarted = GetTickCount64();
			RemoteBootstrapStatus bootstrapStatus = {};
			for(;;)
			{
				process.readMemory(remoteStatus, &bootstrapStatus, sizeof(bootstrapStatus));
				if( bootstrapStatus.stage == 4 || bootstrapStatus.stage >= 0xE0 ) break;
				if( WaitForSingleObject(pInfo.hProcess, 0) == WAIT_OBJECT_0 )
					throw std::exception("Leeyes exited during DLL bootstrap");
				if( GetTickCount64() - injectionWaitStarted >= 30000 )
					throw std::exception("DLL bootstrap did not report completion within 30 seconds");
				Sleep(10);
			}
			WriteLauncherDiagnostic(TEXT("dll_loadlibrary_result"),
				bootstrapStatus.loadLibraryResult);
			WriteLauncherDiagnostic(TEXT("dll_initializer_export"),
				bootstrapStatus.getProcAddressResult);
			WriteLauncherDiagnostic(
				bootstrapStatus.stage == 4 ? TEXT("dll_initializer_completed") :
				TEXT("dll_bootstrap_failed"),
				bootstrapStatus.stage);
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
			WriteLauncherDiagnostic(TEXT("injector_exception"));
			std::cout << "Error while trying to inject dll into process: " << e.what() << std::endl;
			ResumeThread(pInfo.hThread);
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
