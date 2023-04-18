#pragma once

#include "windows.h"
#include <vector>

#include "Helpers.h"

namespace Detectors {

	extern std::vector<PCSTR> SyscallsAllowOpenProcess;
	extern PCSTR SyscallAllowOpenThread;
	extern PCSTR SyscallAllowSetThreadContext;

	VOID DirectSyscall ( DWORD pid, HANDLE hProcess, std::vector<ULONG_PTR> stack );
	VOID InDirectSyscall ( DWORD pid, HANDLE hProcess, std::vector<ULONG_PTR> stack, PCSTR );

}