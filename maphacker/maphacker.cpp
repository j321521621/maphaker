// maphacker.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <string>
using std::string;
using std::wstring;

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


wstring GetFileVer(wstring FileName) 
{ 
	TCHAR  SubBlock[64]; 
	DWORD  InfoSize; 
	InfoSize = GetFileVersionInfoSize(FileName.c_str(),NULL);        if(InfoSize==0) return 0; 
	TCHAR *InfoBuf = new TCHAR[InfoSize];  
	GetFileVersionInfo(FileName.c_str(),0,InfoSize,InfoBuf); 
	unsigned int  cbTranslate = 0; 
	struct LANGANDCODEPAGE
	{ 
		WORD wLanguage; 
		WORD wCodePage; 
	}
	*lpTranslate; 
	VerQueryValue(InfoBuf, TEXT("\\VarFileInfo\\Translation"), 
		(LPVOID*)&lpTranslate,&cbTranslate); 
	// Read the file description for each language and code page. 
	wsprintf( SubBlock,  
		TEXT("\\StringFileInfo\\%04x%04x\\FileVersion"), 
		lpTranslate[0].wLanguage, 
		lpTranslate[0].wCodePage); 
	void *lpBuffer=NULL; 
	unsigned int dwBytes=0; 
	VerQueryValue(InfoBuf, SubBlock, &lpBuffer, &dwBytes);  
	wstring ret((LPWSTR)lpBuffer,dwBytes-1);
	delete[] InfoBuf; 
	return ret; 
}



enum WC3VER{
	V_124E=124,
	V_UNKNOWN=0
};

enum OPENTYPE{
	BIG,
	SMALL
};

WC3VER GetWar3Ver(wstring path)
{
	wstring version=GetFileVer(path);
	if(version==L"1, 24, 4, 6387")
	{
		return V_124E;
	}
	else
	{
		return V_UNKNOWN;
	}
}

class patcher
{
public:
	patcher (HANDLE hWar3Process,DWORD base,DWORD i, string data):
	  m_process(hWar3Process),
	  m_addr((LPVOID)(base+i)),
	  m_buf(data)
	{
		
	}

	BOOL patch()
	{
		DWORD tempsz=m_buf.size();
		char* tempbuf=new char[tempsz];
		DWORD readbyte=0;

		ReadProcessMemory(m_process,m_addr,tempbuf,tempsz,&readbyte);
		if(readbyte!=m_buf.size())
		{
			delete tempbuf;
			return FALSE;
		}
		
		if(WriteProcessMemory(m_process,m_addr,m_buf.c_str(),m_buf.size(),0))
		{
			m_buf=string(tempbuf,tempsz);
			delete tempbuf;
			return TRUE;
		}

		delete tempbuf;
		return FALSE;
	}

private:
	HANDLE m_process;
	LPVOID m_addr;
	string m_buf;
};

BOOL patch(HANDLE hWar3Process,DWORD base,DWORD i, string data) 
{
	LPCCH src=data.c_str();
	DWORD sz=data.size();
	printf("patch 0x%08x with %d bytes\n",src,sz);
	return WriteProcessMemory(hWar3Process,(LPVOID)(base+i),src,sz,0);
}

BOOL hack(HANDLE hWar3Process,WC3VER War3Ver,DWORD base,OPENTYPE type)
{
	switch(War3Ver)
	{
	case V_124E:
		{
			switch(type)
			{
			case BIG:
				{
					patcher p2(hWar3Process,base,0x39EBBC,"\x75");   
					patcher p3(hWar3Process,base,0x3A2030,"\x90\x90");   
					patcher p4(hWar3Process,base,0x3A20DB,"\x90\x90"); 

					p2.patch();
					p3.patch();
					p4.patch();
					Sleep(20);
					p2.patch();
					p3.patch();
					p4.patch();
				}
				break;
			case SMALL: 
				{
					patcher p2(hWar3Process,base,0x361F7C,string("\x00",1));

					p2.patch();
					Sleep(300);
					p2.patch();
				}
				break;
			}
			return TRUE;
			break;
		}
	case V_UNKNOWN:
		return FALSE;
	}

}

wstring getmodulepath(DWORD pid,wstring modulename)
{
	wstring ret;
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid);
	MODULEENTRY32 module32;
	module32.dwSize = sizeof(module32);
	BOOL bResult = Module32First(hModuleSnap,&module32);
	while(bResult)
	{
		wprintf(L"    [%s = %s]\n",module32.szModule,module32.szExePath);
		if(modulename==module32.szModule)
		{
			ret=module32.szExePath;
			bResult=FALSE;
		}
		else
		{
			bResult = Module32Next(hModuleSnap,&module32);
		}
	}

	CloseHandle(hModuleSnap);
	return ret;
}




DWORD openmap(OPENTYPE type)
{

	if(EnableDebugPriv())
	{
		printf("enabledebugpriv successed\n");
	}
	else
	{
		printf("enabledebugpriv failed\n");
		return FALSE;
	}

	DWORD pid=GetPIDForProcess(L"War3.exe");
	if(!pid)
	{
		pid=GetPIDForProcess(L"War3.exe *32");
	}
	if(!pid)
	{
		pid=GetPIDForProcess(L"war3.exe");
	}
	if(!pid)
	{
		pid=GetPIDForProcess(L"war3.exe *32");
	}

	if(pid)
	{
		printf("find War3.exe successed: %d\n",pid);
	}
	else
	{
		printf("find War3.exe failed\n");
		return FALSE;
	}

	wstring gamedllpath=getmodulepath(pid,L"Game.dll");
	if(gamedllpath.size())
	{
		wprintf(L"get game.dll path successed: %s\n",gamedllpath.c_str());
	}
	else
	{
		printf("get game.dll path failed\n");
		return FALSE;
	}


	WC3VER war3ver=GetWar3Ver(gamedllpath);
	if(war3ver!=V_UNKNOWN)
	{
		printf("get game.dll version successed: %d\n",war3ver);
	}
	else
	{
		printf("get game.dll version failed\n");
		return FALSE;
	}

	HANDLE hWar3Process=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	if(hWar3Process)
	{
		printf("openprocess successed\n");
	}
	else
	{
		printf("openprocess failed\n");
		return FALSE;
	}


	DWORD base=GetGameDLLAddr(hWar3Process,L"game.dll");
	if(base)
	{
		printf("get dll base adreess successed: 0x%08x\n",base);
	}
	else
	{
		printf("get dll base adreess failed\n");
		CloseHandle(hWar3Process);
		return FALSE;
	}

	//DWORD rslt=hack(hWar3Process,war3ver,base,type);
	printf("mapkack successd\n");
	CloseHandle(hWar3Process);
	return TRUE;
}

int _tmain(int argc, _TCHAR* argv[])
{
	if(!RegisterHotKey(NULL,0,MOD_NOREPEAT,VK_OEM_PLUS))
	{
		printf("registerhotkey failed\n");
		return -1;
	}

	if(!RegisterHotKey(NULL,1,MOD_NOREPEAT,VK_OEM_MINUS))
	{
		printf("registerhotkey failed\n");
		return -1;
	}

	MSG msg;
	BOOL bRet;

	while( (bRet = GetMessage( &msg, NULL, 0, 0 )) != 0)
	{ 
		TranslateMessage(&msg);
		if(msg.message==WM_HOTKEY)
		{
			if(msg.wParam==0)
			{
				printf("====get hot key for open big map====\n");
				openmap(BIG);
			}
			if(msg.wParam==1)
			{
				printf("====get hot key for open mini map====\n");
				openmap(SMALL);
			}
		}
		else
		{
			DispatchMessage(&msg);
		}
	}
}