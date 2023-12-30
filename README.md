# ProcGuard

This repository contains a C program designed to detect process injection attempts on a Windows system. Process injection is a prevalent tactic employed by malware to insert code into the address space of other processes. ProcGuard is specifically engineered to vigilantly monitor and pinpoint suspicious activities related to process handles

## Features
**1.** Injection Detection: ProcGuard excels in detecting a wide array of injection techniques, including but not limited to:

> `1.` Standard DLL Injection / Memory Module injection

> `2.` Reflective DLL Injection

> `3.` Some variants of Thread Hijacking

> `4.` Some variants of Atom Bombing

> `5.` Asynchronous Procedure Call (APC) Injections [or QueueUserAPC Payload Injection]

> `6.` Process Hollowing

> `7.` PE Injection

> `8.` COM Object Injection

> `9.` Every API Hooking that needs to call OpenProcess

> `10.` Thread Local Storage injection

> `11.` Shellcode Injections that requires suspending threads

> `12.` DLL Sideloading

> `13.` Process Overwriting (https://github.com/hasherezade/process_overwriting)

> `14.` Module Overloading (https://github.com/hasherezade/module_overloading)

> `15.` Transacted Hollowing (https://github.com/hasherezade/transacted_hollowing)

**2.** Handle Inspection: The tool inspects handles associated with each running process, identifying any unauthorized access attempts.

**3.** Targeted Process Protection: Users can specify a target process by name (e.g., javaw.exe) that the tool will monitor for injection attempts.

**4.** Real-time Monitoring: The program continuously monitors processes and provides real-time alerts when injection attempts are detected.

## Prerequisites
> **1.** Operating System: Windows

> **2.** Compiler: Microsoft Visual Studio or equivalent

> **3.** C standard: ISO C17 (2018 - Latest C standard)

> **4.** Dependencies: None

## Usage
> **1.** Build the Program:

- Compile the code using a C compiler, such as Microsoft Visual Studio.
- If you prefer, you can just download the compiled binary in the "Releases" section of this repository.

> **2.** Run the Executable:

- Execute the generated binary on a Windows system.

> **3.** Input Target Process Name:

- When prompted, enter the name of the process you want to protect (e.g., ScreenshareTool.exe).

> **4.** Monitor Process Activity:

- The tool will continuously monitor processes and display alerts if injection attempts are detected.

## Code Structure

- InspectHandle: Function to inspect handles for unauthorized access.

- EnumerateProcesses: Function to iterate through running processes and inspect handles.

- wcscasecmp: Case-insensitive string comparison function.

- GetProcessIdByName: Function to retrieve the process ID based on the process name.

- main: The main program that initiates the monitoring process.

## Disclaimer
This tool is provided as-is, without any warranty or guarantee. It is intended for educational and informational purposes only. Use it responsibly and at your own risk.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
