# Hunt-Weird-Syscalls

This project aims to identify (some) abnormally conducted syscalls by leveraging ``ETW``.   

``ETW`` providers sitting in the kernel can effectively be leveraged, as the calltraces of the emitted events contain the address from where the syscall was conducted.

This allows monitoring for two techniques often used by threat actors: ``direct`` and ``indirect`` syscalls:

1: A syscall was conducted from an untrusted module (=direct syscall)   
2: The used syscall stub does not match the conducted syscall (=indirect syscall)

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


## Credits

- [KrabsETW](https://github.com/microsoft/krabsetw) 
- [SysWhispers3](https://github.com/klezVirus/SysWhispers3)
- [etw provider docs by repnz](https://github.com/repnz/etw-providers-docs)
- [@OutflankNL](https://twitter.com/OutflankNL) for ``IsElevated()``
