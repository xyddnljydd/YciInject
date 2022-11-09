#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(__stdcall* PZwLoadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(__stdcall* PZwUnloadDriver)(PUNICODE_STRING DriverServiceName);

UNICODE_STRING g_Name = { 0 };
PZwLoadDriver g_ZwLoadDriver = NULL;
PZwUnloadDriver g_ZwUnloadDriver = NULL;

void RequirePrivilege(LPCTSTR lpPrivilege) 
{
	HANDLE hToken;
	BOOL bErr = FALSE;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	bErr = LookupPrivilegeValue(NULL, lpPrivilege, &luid);
	if (bErr != TRUE)
		return ;
	bErr = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (bErr != TRUE)
		return ;
	if (ANYSIZE_ARRAY != 1)
		return ;
	tp.PrivilegeCount = 1; 
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	bErr = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (bErr != TRUE || GetLastError() != ERROR_SUCCESS) 
		return ;
	CloseHandle(hToken);
	return ;
}

void init()
{
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	
	if (!hNtdll)
		return;
	g_ZwLoadDriver = (PZwLoadDriver)GetProcAddress(hNtdll, "NtLoadDriver");
	g_ZwUnloadDriver = (PZwUnloadDriver)GetProcAddress(hNtdll, "NtUnloadDriver");
	RtlInitUnicodeString(&g_Name, (PVOID)L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Yci");
}

void unloadDriver()
{
	if (g_ZwUnloadDriver)
	{
		NTSTATUS nStatus = g_ZwUnloadDriver(&g_Name);
		if (nStatus == 0)
			printf("UnloadDriver Success");
		else
			printf("UnloadDriver:%X\n", nStatus);
		RegDeleteKeyA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Yci");
	}
}

void loadDriver(char* path)
{
	HKEY hk;
	DWORD type = 1;
	DWORD start = 3;
	DWORD errorControl = 0;
	if (g_ZwLoadDriver)
	{
		RegDeleteKeyA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Yci");
		RegCreateKeyA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Yci", &hk);
		RegSetValueExA(hk, "Type", 0, REG_DWORD, (LPBYTE)& type, sizeof(DWORD));
		RegSetValueExA(hk, "Start", 0, REG_DWORD, (LPBYTE)& start, sizeof(DWORD));
		RegSetValueExA(hk, "ImagePath", 0, REG_EXPAND_SZ, (LPBYTE)path, (DWORD)strlen(path));
		RegSetValueExA(hk, "DisplayName", 0, REG_SZ, (LPBYTE)"Yci", (DWORD)strlen("Yci"));
		RegSetValueExA(hk, "ErrorControl", 0, REG_DWORD, (LPBYTE)& errorControl, sizeof(DWORD));
		NTSTATUS nStatus = g_ZwLoadDriver(&g_Name);
		if (nStatus == 0)
			printf("LoadDriver Success");
		else
			printf("NtLoadDriver:%X\n", nStatus);
	}
}

int main()
{
	init();
	RequirePrivilege(SE_LOAD_DRIVER_NAME);
	loadDriver("\\??\\C:\\Users\\yongcai\\Desktop\\Yci.sys");
	system("pause");
	unloadDriver();
}