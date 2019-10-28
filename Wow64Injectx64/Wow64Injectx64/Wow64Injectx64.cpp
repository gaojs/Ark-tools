// Wow64InjectX64.cpp : 定义控制台应用程序的入口点。
#include "stdafx.h"
#include "Wow64Injectx64.h"
#include <memory>
#include <string>
#include <Windows.h>
#include "wow64ext.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#pragma comment(lib,"wow64ext.lib")

// 唯一的应用程序对象
CWinApp theApp;

using namespace std;

typedef struct _UNICODE_STRING {
	USHORT    Length;     //UNICODE占用的内存字节数，个数*2；
	USHORT	  MaximumLength; 
	DWORD64   Buffer;     //注意这里指针的问题
} UNICODE_STRING ,*PUNICODE_STRING;

unsigned char shell_code[] = {
	0x48, 0x89, 0x4c, 0x24, 0x08,                               // mov       qword ptr [rsp+8],rcx 
	0x57,                                                       // push      rdi
	0x48, 0x83, 0xec, 0x20,                                     // sub       rsp,20h
	0x48, 0x8b, 0xfc,                                           // mov       rdi,rsp
	0xb9, 0x08, 0x00, 0x00, 0x00,                               // mov       ecx,8
	0xb8, 0xcc, 0xcc, 0xcc, 0xcc,                               // mov       eac,0CCCCCCCCh
	0xf3, 0xab,                                                 // rep stos  dword ptr [rdi]
	0x48, 0x8b, 0x4c, 0x24, 0x30,                               // mov       rcx,qword ptr [__formal]
	0x49, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       r9,0  //PVOID*  BaseAddr opt
	0x49, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       r8,0  //PUNICODE_STRING Name
	0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rdx,0
	0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rcx,0
	0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rax,0 
	0xff, 0xd0,                                                 // call      rax   LdrLoadDll
	0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rcx,0
	0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov       rax,0
	0xff, 0xd0                                                  // call      rax
};

enum struct InjectResult{
	OK,
	Error_NoSuchFile,
	Error_OpenProcess,
	Error_VirtualAllocEx,
	Error_GetProcAddress,
	Error_WriteProcessMemory,
	Error_CreateRemoteThread,
};

InjectResult Wow64InjectX64(DWORD processId, const TCHAR* filePath)
{	
	if (!PathFileExists(filePath))
	{
		return InjectResult::Error_NoSuchFile;
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (INVALID_HANDLE_VALUE == hProcess)
	{
		return InjectResult::Error_OpenProcess;
	}

	size_t filePathLen = (size_t)::_tcslen(filePath);
	size_t paramSize = (filePathLen+1) * sizeof(TCHAR)
		+ sizeof(UNICODE_STRING) + sizeof(DWORD64);
	DWORD64 pMemAddr = (DWORD64)VirtualAllocEx64(hProcess,
		NULL, paramSize, MEM_COMMIT, PAGE_READWRITE);
	size_t shellCodeLen = sizeof(shell_code);
	DWORD64  pShellAddr = (DWORD64)VirtualAllocEx64(hProcess,
		NULL, shellCodeLen, MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	if ((!pMemAddr) || (!pShellAddr))
	{
		return InjectResult::Error_VirtualAllocEx;
	}
	
	char * pMemLocal = new char[paramSize];
	memset(pMemLocal, 0, paramSize);

	PUNICODE_STRING pWideStr = (PUNICODE_STRING)(pMemLocal + sizeof(DWORD64));
	pWideStr->Length = (USHORT)filePathLen;
	pWideStr->MaximumLength = (USHORT)filePathLen*2;
	wcscpy((WCHAR*)(pWideStr+1), filePath);
	pWideStr->Buffer = pMemAddr + sizeof(DWORD64) + sizeof(UNICODE_STRING);

	DWORD64 ntdll64 = GetModuleHandle64(L"ntdll.dll");
	DWORD64 ldrLoadDll = GetProcAddress64(ntdll64,"LdrLoadDll");
	DWORD64 rtlCreateUserThread = GetProcAddress64(ntdll64,"RtlCreateUserThread");
	DWORD64 rtlExitThread = GetProcAddress64(ntdll64,"RtlExitUserThread");
	if (NULL == ldrLoadDll || NULL==rtlCreateUserThread || NULL==rtlExitThread)
	{
		return InjectResult::Error_GetProcAddress;
	}

	//r9
	memcpy(shell_code+32, &pMemAddr, sizeof(DWORD64));

	//r8
	DWORD64 ptr = pMemAddr + sizeof(DWORD64);
	memcpy(shell_code+42, &ptr, sizeof(PUNICODE_STRING));

	//LdrLoadDll
	memcpy(shell_code+72, &ldrLoadDll, sizeof(DWORD64));

	//RtlExitUserThread
	memcpy(shell_code+94, &rtlExitThread, sizeof(DWORD64));
	size_t write_size = 0;
	if (!WriteProcessMemory64(hProcess, pMemAddr, pMemLocal, paramSize, NULL) ||
		!WriteProcessMemory64(hProcess, pShellAddr, shell_code, shellCodeLen, NULL))
	{
		return InjectResult::Error_WriteProcessMemory;
	}
	DWORD64 hRemoteThread = 0;
	struct {
		DWORD64 UniqueProcess;
		DWORD64 UniqueThread;
	} clientId;
	DWORD64 ret = X64Call(rtlCreateUserThread, 10,
		(DWORD64)hProcess,					// ProcessHandle
		(DWORD64)NULL,                      // SecurityDescriptor
		(DWORD64)FALSE,                     // CreateSuspended
		(DWORD64)0,                         // StackZeroBits
		(DWORD64)NULL,                      // StackReserved
		(DWORD64)NULL,                      // StackCommit
		pShellAddr,					// StartAddress
		(DWORD64)NULL,                      // StartParameter
		(DWORD64)&hRemoteThread,            // ThreadHandle
		(DWORD64)&clientId);               // ClientID)
	if (INVALID_HANDLE_VALUE == (HANDLE)hRemoteThread)
	{
		return InjectResult::Error_CreateRemoteThread;
	}
	return InjectResult::OK;
}

int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	printf("查看并输入要注入进程的ID：");
	ULONG_PTR processID = 0;
	cin >> processID;

	WCHAR filePath[] = L"D:\\conDll64.dll";
	if (InjectResult::OK == Wow64InjectX64(processID, filePath))
	{
		printf("Inject Success!\n");
	}
	return 0;
}