#include "../libs/krabs/krabs.hpp"

#include "Detectors.h"
#include "Helpers.h"

#define EVENTID_SETTHTREADCONTEXT 4
#define EVENTID_OPENTHREAD 6

VOID EnableAuditApiTracing ( krabs::user_trace& );
VOID OnObservableSyscall ( const EVENT_RECORD&, const krabs::trace_context& );

VOID EnableAuditApiTracing ( krabs::user_trace& userTrace ) {

	krabs::provider<>* providerApiTracing = new krabs::provider<> ( L"Microsoft-Windows-Kernel-Audit-API-Calls" );

	providerApiTracing->trace_flags ( providerApiTracing->trace_flags ( ) | EVENT_ENABLE_PROPERTY_STACK_TRACE );

	krabs::event_filter* filterOpenThread = new krabs::event_filter ( krabs::predicates::id_is ( EVENTID_OPENTHREAD ) ); // OpenThread
	krabs::event_filter* filterSetContextThread = new krabs::event_filter ( krabs::predicates::id_is ( EVENTID_SETTHTREADCONTEXT ) ); // OpenThread

	/* For now no distinction between events */
	filterOpenThread->add_on_event_callback ( OnObservableSyscall );
	filterSetContextThread->add_on_event_callback ( OnObservableSyscall );

	providerApiTracing->add_filter ( *filterSetContextThread );
	providerApiTracing->add_filter ( *filterOpenThread );

	userTrace.enable ( *providerApiTracing );

}

VOID OnObservableSyscall ( const EVENT_RECORD& record, const krabs::trace_context& trace_context ) {

	BOOL bSuccess = FALSE;
	HANDLE hProcess = NULL;
	DWORD pid = 0;

	krabs::schema schema ( record, trace_context.schema_locator );
	krabs::parser parser ( schema );
	std::vector<ULONG_PTR> stack;

	pid = record.EventHeader.ProcessId;
	stack = schema.stack_trace ( );

	if ( pid == GetCurrentProcessId ( ) )
		return;

	Helpers::RemoveKernelAddrs ( stack );
	if ( stack.size ( ) == 0 )
		return;

	hProcess = OpenProcess ( PROCESS_ALL_ACCESS, FALSE, pid );
	if ( hProcess == NULL )
		return;

	Detectors::DirectSyscall ( pid, hProcess, stack );

	if ( record.EventHeader.EventDescriptor.Id == EVENTID_OPENTHREAD )
		Detectors::InDirectSyscall ( pid, hProcess, stack, Detectors::SyscallAllowOpenThread);
	else if ( record.EventHeader.EventDescriptor.Id == EVENTID_SETTHTREADCONTEXT )
		Detectors::InDirectSyscall ( pid, hProcess, stack, Detectors::SyscallAllowSetThreadContext );

Cleanup:

	if ( hProcess )
		CloseHandle ( hProcess );

}

VOID Go ( krabs::user_trace* userTrace ) {
	userTrace->start ( );
}

int main ( int argc, char** argv ) {

	HANDLE traceThread = NULL;

	krabs::user_trace userTrace ( L"Hunt-Weird-Syscalls" );

	if ( !Helpers::IsElevated ( ) ) {
		printf ( "- Not elevated\n" );
		return 0;
	}

	printf ( "* Enabling trace, might take a bit ... \n" );

	EnableAuditApiTracing ( userTrace );
	traceThread = CreateThread ( NULL, 0, ( LPTHREAD_START_ROUTINE ) Go, &userTrace, 0, NULL );
	if ( traceThread == NULL )
		return 0; // o.0

	printf ( "* Started monitoring, press any key to exit ... \n" );

	getchar ( );
	printf ( "* exiting ... \n" );
	userTrace.stop ( );
	WaitForSingleObject ( traceThread, INFINITE );

	return 0;

}