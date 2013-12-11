// maphacker.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <string>
using std::string;

#pragma comment(lib, "Version.lib")

BOOL EnableDebugPriv()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) 
	{
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME,&sedebugnameValue))
	{
		CloseHandle(hToken);
		return FALSE;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL)) 
	{
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);
	return TRUE;
}

DWORD GetPIDForProcess(LPTSTR process)//获取进程ID
{
	BOOL                    working;
	PROCESSENTRY32          lppe= {0};
	DWORD                   targetPid=0;
	HANDLE hSnapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS ,0);
	if (hSnapshot)
	{
		lppe.dwSize=sizeof(lppe);
		working=Process32First(hSnapshot,&lppe);
		while (working)
		{
			if(wcscmp(lppe.szExeFile,process)==0)
			{
				targetPid=lppe.th32ProcessID;
				break;
			}working=Process32Next(hSnapshot,&lppe);
		}
	}
	CloseHandle( hSnapshot );
	return targetPid;
}

typedef enum _MEMORY_INFORMATION_CLASS   
{  
	MemoryBasicInformation,  
	MemoryWorkingSetList,  
	MemorySectionName,  
	MemoryBasicVlmInformation  
} MEMORY_INFORMATION_CLASS;  

typedef long (NTAPI * PF_ZwQueryVirtualMemory)   
	(         IN HANDLE ProcessHandle,  
	IN PVOID BaseAddress,  
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,  
	OUT PVOID MemoryInformation,  
	IN ULONG MemoryInformationLength,  
	OUT PULONG ReturnLength OPTIONAL   
	);  
typedef struct _UNICODE_STRING  
{  
	USHORT Length;  
	USHORT MaximumLength;  
	PWSTR Buffer;  
} UNICODE_STRING, *PUNICODE_STRING;  

DWORD GetGameDLLAddr(HANDLE hWar3Handle,WCHAR * ModuleName)  
{  
	DWORD startAddr;  
	BYTE buffer[MAX_PATH*2+4];  
	MEMORY_BASIC_INFORMATION memBI;  
	PUNICODE_STRING secName;     
	PF_ZwQueryVirtualMemory ZwQueryVirtualMemory;  

	startAddr = 0x00000000;  
	ZwQueryVirtualMemory = (PF_ZwQueryVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll"),"ZwQueryVirtualMemory");  
	do{  
		if(ZwQueryVirtualMemory(hWar3Handle,(PVOID)startAddr,MemoryBasicInformation,&memBI,sizeof(memBI),0 ) >= 0 &&  
			(memBI.Type == MEM_IMAGE))  
		{  
			if( ZwQueryVirtualMemory(hWar3Handle,(PVOID)startAddr,MemorySectionName,buffer,sizeof(buffer),0 ) >= 0 )  
			{  
				secName = (PUNICODE_STRING)buffer;  
				if(wcsicmp(ModuleName, wcsrchr(secName->Buffer,'\\')+1) == 0)  
				{  
					return startAddr;  
				}  
			}
		}  
		startAddr += 0x10000;  
	}  
	while( startAddr < 0x80000000 );  
	return 0;  
};  

enum WC3VER{_UN,_120E,_124B,_124E,_125B,_126B};


void PATCH(HANDLE hWar3Process,DWORD base,DWORD i, string data) 
{
	LPCCH src=data.c_str();
	DWORD sz=data.size();
	DWORD ret=WriteProcessMemory(hWar3Process,(LPVOID)(base+i),src,sz,0);
}

BOOL hack(HANDLE hWar3Process,WC3VER War3Ver)
{
	DWORD base=GetGameDLLAddr(hWar3Process,L"game.dll");
	if(!base)
	{
		return FALSE;
	}

	switch(War3Ver)
	{
	case _124E:
		//大地图去除迷雾   
		PATCH(hWar3Process,base,0x74D1B9,string("\xB2\x00\x90\x90\x90\x90",6));   
		//大地图显示单位   
		PATCH(hWar3Process,base,0x39EBBC,"\x75");   
		PATCH(hWar3Process,base,0x3A2030,"\x90\x90");   
		PATCH(hWar3Process,base,0x3A20DB,"\x90\x90"); 
		break;
	case _UN:
	default:
		break;
	}
}



int _tmain(int argc, _TCHAR* argv[])
{
	if(!EnableDebugPriv())
	{
		printf("enabledebugpriv failed\n");
		return -1;
	}

	DWORD pid=GetPIDForProcess(L"War3.exe");
	if(!pid)
	{
		printf("not found War3.exe\n");
		return -2;
	}

	HANDLE hWar3Process=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	if(!hWar3Process)
	{
		printf("openprocess failed\n");
		return -3;
	}



	hack(hWar3Process,_124E);
	return 0;
}

