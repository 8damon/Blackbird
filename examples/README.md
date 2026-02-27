# Sleepwalker Examples

- `direct_syscall_ntqueryvm.cpp`
- Executes `NtQueryVirtualMemory` through the `ntdll` export and then via a stack-resident syscall stub using the extracted SSN.
- Use this example to validate SLEEPWALKER direct-syscall detection and stack/origin reporting.

Build output:

- `x64\Debug\SleepwalkerExampleDirectSyscallNtQueryVm.exe`
- `x64\Release\SleepwalkerExampleDirectSyscallNtQueryVm.exe`

Add more examples by creating new `.cpp` files in this folder and adding a corresponding `vcxproj` entry (or a new example project) under `vcxproj/`.
