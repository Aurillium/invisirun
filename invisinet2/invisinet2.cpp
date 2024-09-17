#include "pch.h"

#include "invisinet2.h"
#include "ntdll.h"
#pragma comment(lib, "ntdll.lib")

#include <msclr/marshal.h>
using namespace invisinet2;
using namespace System;

// This is just easier
struct RunLocals {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    PWSTR uFake;
    PWSTR uReal;
    USHORT fakeLength;
    USHORT realLength;

    PROCESS_BASIC_INFORMATION pbi;
    DWORD retLen;
    SIZE_T bytesRead;
    SIZE_T bytesWritten;
    HANDLE allocMemAddress;
    PEB pebLocal;
    RTL_USER_PROCESS_PARAMETERS parameters;
};

bool Invisirun::Run(String^ fake, String^ real) {
    // Allocate space for all the locals at once because I'm a good programmer.
    RunLocals* locals = (RunLocals*)_aligned_malloc(sizeof(RunLocals), __alignof(RunLocals));
    if (locals == NULL) {
        Console::WriteLine("Could not allocate memory for locals.");
        return false;
    }

	PWSTR uFake = static_cast<PWSTR>(Runtime::InteropServices::Marshal::StringToHGlobalUni(fake).ToPointer());
	PWSTR uReal = static_cast<PWSTR>(Runtime::InteropServices::Marshal::StringToHGlobalUni(real).ToPointer());

	if (!CreateProcessW(NULL, uFake, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, L"C:\\Windows\\System32\\", &locals->si, &locals->pi)) {
		Console::WriteLine("Could not create new process.");
		return false;
	}

    // READ STARTUP INFO
    NtQueryInformationProcess(locals->pi.hProcess, ProcessBasicInformation, &locals->pbi, sizeof(locals->pbi), &locals->retLen);

    // Read the PEB from the target process
    if (!ReadProcessMemory(locals->pi.hProcess, locals->pbi.PebBaseAddress, &locals->pebLocal, sizeof(PEB), &locals->bytesRead)) {
        Console::WriteLine("Could not call ReadProcessMemory to grab PEB\n");
        return false;
    }

    // Grab the ProcessParameters from PEB
    ReadProcessMemory(locals->pi.hProcess, locals->pebLocal.ProcessParameters, &locals->parameters, sizeof(locals->parameters), &locals->bytesRead);
    if (locals->parameters.CommandLine.Buffer == NULL) {
        Console::WriteLine("Warning: Commandline arguments appear to be null?\n");
    }

    locals->allocMemAddress = VirtualAllocEx(locals->pi.hProcess, NULL, locals->realLength, MEM_COMMIT, PAGE_READWRITE);
    if (locals->allocMemAddress == NULL) {
        Console::WriteLine("Failed to allocate memory in new process.\n");
        return false;
    }
    
    if (!WriteProcessMemory(locals->pi.hProcess, locals->allocMemAddress, uReal, locals->realLength, &locals->bytesWritten)) {
        Console::WriteLine("Could not call WriteProcessMemory to write into new argument buffer.\n");
        return false;
    }

    if (!WriteProcessMemory(locals->pi.hProcess, locals->pebLocal.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Buffer), &locals->allocMemAddress, sizeof(locals->allocMemAddress), &locals->bytesWritten)) {
        Console::WriteLine("Could not call WriteProcessMemory to update commandline args.\n");
        return false;
    }

    // Resume thread execution
    ResumeThread(locals->pi.hThread);

    CloseHandle(locals->pi.hThread);
    CloseHandle(locals->pi.hProcess);

	return true;
}