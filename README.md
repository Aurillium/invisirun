# invisirun

### A new and (hopefully) improved commandline spoofing PoC

##### Quick note: This repo is synced every once in a while with a currently private other repo I'm working on, so commit messages are a bit cursed, and most of the projects are experimental and not working. `invisirun` is the project you want.

## What?
Usually commandline spoofing requires the real arguments to be of equal or shorter length to the fake arguments that appear in logs, however this technique uses a low-level API to bypass this limitation, allowing users to execute commands up to 32767 characters while appearing as short as the cover command to Sysmon.

## How?
This technique uses `NtCreateUserProcess` to start the process rather than `CreateProcess`, as it gives us finer control over the arguments we pass. On this level commandline arguments are passed as a `UNICODE_STRING`, which is comprised of lengths and a buffer. The default method of creating one of these strings (`RtlInitUnicodeString`) creates a string that has an internal length matching that of the buffer, and this is the function used internally by `CreateProcess` to set up the commandline arguments of a process to pass to `NtCreateUserProcess`. My technique uses a custom function (`SupersizeUString`) to set up a unicode string with a buffer of a custom length and padding all unused bytes with 0. This allows us to later overwrite the arguments with significantly longer strings. After the process is started, this technique mostly follows the original PoC.

## Results?
Because arguments and the executable path are completely separate in `NtCreateUserProcess`, we can run commands with any arguments, including none at all. It should be noted that in logging software, the executable path is usually shown and using a different executable path in the arguments may be more easily detected. Because the length requirements are now removed, commands of any length can be run and the cover arguments don't look padded in some logging software.

System Informer updates the "Command line" field on every write to the PEB, so this will be updated to the new argument buffer, but to mitigate this invisirun will set the length of the internal `UNICODE_STRING` to the length of the cover arguments so that the cover command can be set to the beginning of the real command and System Informer and logging software will match.
Other PoCs write the fake arguments back to the process, which could be implemented fairly easily here too.

### The Problem
Unfortunately since 4688 security log EVIDs don't work on my testing VM, I did not realise at first that I've actually made the exploit more detectable in Windows Security Logs. So although the trailing spaces are gone from Sysmon, they seem to appear as newlines in security logs.

## Credits

This technique could not have been developed without [BlackOfWorld's NtCreateUserProcess repo](https://github.com/BlackOfWorld/NtCreateUserProcess); much of the NtCreateUserProcess code comes from here. `ntdll.h` also comes from [x64dbg's TitanEngine](https://github.com/x64dbg/TitanEngine).
