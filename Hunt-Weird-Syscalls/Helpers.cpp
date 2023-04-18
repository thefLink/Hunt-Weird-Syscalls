#include "Helpers.h"

namespace Helpers {

	BOOL ModuleNameFromAddress ( HANDLE hProcess, PVOID pAddr, std::string& moduleName ) {

		BOOL bSuccess = FALSE;
		SIZE_T s = 0;
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		CHAR cmoduleName [ MAX_PATH ] = { 0 };

		s = VirtualQueryEx ( hProcess, ( LPCVOID ) pAddr, &mbi, sizeof ( MEMORY_BASIC_INFORMATION ) );
		if ( s == 0 )
			goto Cleanup;

		bSuccess = K32GetModuleBaseNameA ( hProcess, ( HMODULE ) mbi.AllocationBase, ( LPSTR ) cmoduleName, MAX_PATH );
		if ( bSuccess == FALSE )
			goto Cleanup;

		moduleName = std::string ( cmoduleName );

		bSuccess = TRUE;

	Cleanup:

		return bSuccess;

	}

	VOID RemoveKernelAddrs ( std::vector<ULONG_PTR>& stack ) {

		auto it = stack.begin ( );
		while ( it != stack.end ( ) ) {

			ULONG_PTR addr = *it;
			if ( addr > 0xFFFF000000000000 ) {
				it = stack.erase ( it );
			}
			else {
				++it;
			}

		}

	}

	//https://github.com/outflanknl/Dumpert/blob/master/Dumpert/Outflank-Dumpert/Dumpert.c Is Elevated() was taken from here :).
	BOOL IsElevated ( VOID ) {
		BOOL fRet = FALSE;
		HANDLE hToken = NULL;
		if ( OpenProcessToken ( GetCurrentProcess ( ), TOKEN_QUERY, &hToken ) ) {
			TOKEN_ELEVATION Elevation = { 0 };
			DWORD cbSize = sizeof ( TOKEN_ELEVATION );
			if ( GetTokenInformation ( hToken, TokenElevation, &Elevation, sizeof ( Elevation ), &cbSize ) ) {
				fRet = Elevation.TokenIsElevated;
			}
		}
		if ( hToken ) {
			CloseHandle ( hToken );
		}
		return fRet;
	}


}