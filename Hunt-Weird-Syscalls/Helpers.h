#pragma once
#include "windows.h"
#include "psapi.h"

#include <string>
#include <vector>

namespace Helpers {
	VOID RemoveKernelAddrs ( std::vector<ULONG_PTR>& );
	BOOL ModuleNameFromAddress ( HANDLE, PVOID, std::string& );
	BOOL IsElevated ( VOID );
}