#include <Windows.h>
#include <TlHelp32.h>
#include <Shlwapi.h>
#include <cstdio>

#pragma comment( lib, "Shlwapi" )

bool FindProcessByName(const char* szProcess)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hSnap)
		return false;

	PROCESSENTRY32 pe32{ };
	pe32.dwSize = sizeof(pe32);

	if (!Process32First(hSnap, &pe32))
	{
		CloseHandle(hSnap);
		return false;
	}

	do
	{
		if (StrStrIA(pe32.szExeFile, szProcess))
		{
			CloseHandle(hSnap);
			return true;
		}
	} while (Process32Next(hSnap, &pe32));

	CloseHandle(hSnap);
	return false;
}

bool FindProcessByName(const char* szProcess, DWORD* dwPID)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hSnap)
		return false;

	PROCESSENTRY32 pe32{ };
	pe32.dwSize = sizeof(pe32);

	if (!Process32First(hSnap, &pe32))
	{
		CloseHandle(hSnap);
		return false;
	}

	do
	{
		if (StrStrIA(pe32.szExeFile, szProcess))
		{
			if (dwPID)
				*dwPID = pe32.th32ProcessID;

			CloseHandle(hSnap);
			return true;
		}
	} while (Process32Next(hSnap, &pe32));

	CloseHandle(hSnap);
	return false;
}

bool DumpProcList()
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hSnap)
		return false;

	PROCESSENTRY32 pe32{ };
	pe32.dwSize = sizeof(pe32);

	if (Process32First(hSnap, &pe32))
	{
		do
		{
			printf("%s\n",pe32.szExeFile);
		} while (Process32Next(hSnap, &pe32));
	}

	CloseHandle(hSnap);
	return false;
}

// Create this thread if you wanna check the WindowFromPoint and other user32.dll variants
DWORD WINAPI WindowPointThread(PVOID)
{
	while (true)
	{
		POINT pt{ };
		GetCursorPos(&pt);
		auto hWnd = WindowFromPoint(pt);

		printf("HWND from point 0x%X\n", hWnd);

		if (hWnd)
		{
			DWORD PID = 0;
			GetWindowThreadProcessId(hWnd, &PID);

			if (PID != GetCurrentProcessId())
			{
				// This will also check for process open ( should fail )
				HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
				if (!hProc || hProc == INVALID_HANDLE_VALUE)
				{
					printf("Failed to open process %d\n", GetLastError());
				}
				else
				{
					printf("Process open ok!\n");
					CloseHandle(hProc);
				}
			}
		}

		Sleep(1000);
	}
	return 0;
}

int main()
{
	SetConsoleTitleA("TestHide");

	printf("= Process List Dump =\n\n");
	DumpProcList();
	printf("\n");

	printf("= Specific Process Check =\n\n");

	printf("Cheat Engine found? %s\n", FindProcessByName("cheatengine") ? "Yes" : "No");
	printf("Scylla found? %s\n", FindProcessByName("scylla") ? "Yes" : "No");
	printf("ReClass found? %s\n", FindProcessByName("reclass") ? "Yes" : "No");
	printf("PHacker found? %s\n", FindProcessByName("processhacker") ? "Yes" : "No");
	printf("x64dbg found? %s\n", FindProcessByName("x64dbg") ? "Yes" : "No");
	printf("DbgView found? %s\n", FindProcessByName("DebugView") ? "Yes" : "No");

	printf("\n= Test Process Opening =\n\n");

	DWORD dwPID = NULL;
	FindProcessByName("cheatengine", &dwPID);

	if (dwPID)
	{
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
		if (!hProc || hProc == INVALID_HANDLE_VALUE)
		{
			printf("Failed to open process %d\n", GetLastError());
		}
		else
		{
			printf("Process open ok!\n");
			CloseHandle(hProc);
		}
	}
	else
		printf("PID not found!\n");

	printf("\n= Test Window =\n\n");

	HWND hWnd = FindWindowA(0, "Cheat Engine 7.1");
	if (hWnd)
	{
		printf("Window found!\n");
	}
	else
		printf("Window not found!\n");

	getchar();
	return 0;
}