#include "Detectors.h"

namespace Detectors {

	std::vector<PCSTR> allowedSyscallmodules = { 
		"ntdll.dll", 
		"win32u.dll", 
		"wow64win.dll" 
	};

	PCSTR SyscallAllowOpenThread = "NtOpenThread";
	PCSTR SyscallAllowSetThreadContext = "NtSetContextThread";

	VOID DirectSyscall ( DWORD pid, HANDLE hProcess, std::vector<ULONG_PTR> stack ) {

		std::string lastModule;
		BOOL bSuccess = FALSE;

		bSuccess = Helpers::ModuleNameFromAddress ( hProcess, ( PVOID ) stack.front ( ), lastModule );
		if ( bSuccess == FALSE )
			return;

		for ( auto it = allowedSyscallmodules.begin ( ); it != allowedSyscallmodules.end ( ); ++it ) {
			if ( !_stricmp ( *it, lastModule.c_str ( ) ) )
				return;
		}

		printf ( "! Direct Syscall detected from process: %d\n", pid );
		printf ( "\t Syscall from: 0x%p (%s)\n", ( PVOID ) stack.front ( ), lastModule.c_str ( ) );

	}

	VOID InDirectSyscall ( DWORD pid, HANDLE hProcess, std::vector<ULONG_PTR> stack, PCSTR allowedSyscall ) {

		MEMORY_BASIC_INFORMATION mbi = { 0 };

		std::string lastModule;
		HMODULE hNtdll = NULL;

		BOOL bSuccess = FALSE;
		SIZE_T s = 0;
		ULONG_PTR offsetIs = 0, offsetExpected = 0;
		PVOID returnExpected = NULL;

		bSuccess = Helpers::ModuleNameFromAddress ( hProcess, ( PVOID ) stack.front ( ), lastModule );
		if ( bSuccess == FALSE )
			return;

		if ( _strcmpi ( lastModule.c_str ( ), "ntdll.dll"))
			return; // Currently only verifying ntdll.dll syscalls

		s = VirtualQueryEx ( hProcess, ( LPCVOID ) stack.front ( ), &mbi, sizeof ( MEMORY_BASIC_INFORMATION ) );
		if ( s == 0 )
			return;

		offsetIs = stack.front ( ) - ( ULONG_PTR ) mbi.BaseAddress;
		
		hNtdll = GetModuleHandleA ( "ntdll.dll" );

		returnExpected = GetProcAddress ( hNtdll, allowedSyscall);
		s = VirtualQuery ( returnExpected, &mbi, sizeof ( MEMORY_BASIC_INFORMATION ) );
		if (s == 0) {
			return;
		}

		offsetExpected = ( ( PBYTE ) returnExpected - ( PBYTE ) mbi.BaseAddress );
		if ( offsetExpected < offsetIs && offsetIs <=  offsetExpected + 23 ) {
			return;
		}
		
		printf ( "! Indirect Syscall detected from process: %d\n", pid );
		printf ( "\t Syscall %s expected from: stub at 0x%p but was: 0x%llx\n", allowedSyscall, returnExpected, stack.front ( ) );

	}

}