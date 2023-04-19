# Hunt-Weird-Syscalls

This is a ETW based POC to monitor for abnormal syscalls.   

For now, the syscalls ``NtOpenThread`` and ``NtSetContextThread`` are monitored to identify IOCs indicating both **direct** and **indirect** syscalls.

## Description

This project uses ``ETW``, more precisely kernel based ETW providers, to monitor for IOCs.    
``ETW`` providers sitting in the kernel can effectively be leveraged, as the calltraces of emitted events contain the usermode address from where the syscall was conducted.    

This allows monitoring IOCs indicating direct and indirect syscalls, a technique often leveraged by threat actors:

1: A syscall was conducted from an untrusted module (=direct syscall)   
2: The used syscall stub in ntdll does not match the conducted syscall (=indirect syscall)

This project uses the Provider: ``Microsoft-Windows-Kernel-Audit-API-Calls`` to monitor for ``OpenThread`` and ``SetContextThread`` events triggered by the syscalls ``NtSetContextThread`` or ``NtOpenThread`` respectively.    
Calltraces are enabled, using the flag ``EVENT_ENABLE_PROPERTY_STACK_TRACE``.   

This is a POC, and only monitors two specific syscalls. It is of course possible to use other kernel based providers to enhance telemetry.    

## Tests

This project contains two sample programs using direct and indirect syscalls created using the amazing [SysWhispers3](https://github.com/klezVirus/SysWhispers3).
They were generated as follows:

```
python3 syswhispers.py -a x64 -m jumper_randomized --functions NtSetContextThread
python3 syswhispers.py -a x64 -m embedded --functions NtSetContextThread
```

Upon execution, abnormal syscalls should be identified:

![Identification of Abnormal Syscalls](/Screenshots/1.png?raw=true)

**Tested on ``10.0.19044``.**

## Credits

- [KrabsETW](https://github.com/microsoft/krabsetw) 
- [SysWhispers3](https://github.com/klezVirus/SysWhispers3)
- [etw provider docs by repnz](https://github.com/repnz/etw-providers-docs)
- [@OutflankNL](https://twitter.com/OutflankNL) for ``IsElevated()``
- [@trickster012](https://twitter.com/trickster012) for testing and support <3
