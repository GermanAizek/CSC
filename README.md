# CSC

CSC (CSC.sys / Windows Client-Side Caching Driver / Offline Files) - Windows kernel-mode driver responsible for caching and synchronizing network share files (SMB/MUP) locally for offline access.

My opensource driver does not use the original source codes and is a reverse-engineered driver using [Ghidra](https://en.wikipedia.org/wiki/Ghidra) and [Radare2](https://en.wikipedia.org/wiki/Radare2). The rights have not been violated, and the new driver cannot be signed due to the EV certificate. I hope that the vulnerabilities can be closed using my security patches.

The main goal of the project is to recreate a secure driver with fixed vulnerabilities and errors made by past developers.

### Functions

Driver CSC.sys manages offline caching, synchronization, and local database storage for remote network file systems:

- Client-side caching internal control and request dispatching via METHOD_NEITHER (FSCTL 0x001401A3)
- SMB connection finalization and transition handling (FSCTL 0x001401AC)
- Offline file item query, enumeration, and eviction (IOCTL 0x00140180)
- Local cache store database status and parameter querying (IOCTL 0x00140184)
- Transparent pinning and unpinning of cached items (IOCTL 0x00140188)
- Security descriptor and principal SID translation (IOCTL 0x0014018C)

Fixed vulnerabilities in opensource driver CSC.sys:

- [ ] [LOLDrivers: CSC.sys](https://www.loldrivers.io/drivers/1c92e1bf-103b-4545-b242-e5a9858ec9c8/)
  - Improper Address Validation in IOCTL / FSCTL with METHOD_NEITHER (CVE-2024-26229). Low-privilege users can pass arbitrary kernel addresses via Type3InputBuffer to overwrite kernel structures (such as KTHREAD->PreviousMode) and elevate privileges to NT AUTHORITY\SYSTEM (BYOVD, MITRE ATT&CK T1068).

Fixed no publish vulnerabilities and bugs which contributors to this project found:

- [ ] Device deletion bypassed on symbolic link creation failure ([view code](main.c))
- [ ] Arbitrary memory write and METHOD_NEITHER pointer handling in command 0x001401A3 ([view code](fsctl.c))
- [ ] Cache store database memory corruption and out-of-bounds access in command 0x00140180 ([view code](store.c))
- [ ] Unauthorized privilege escalation and credential spoofing in command 0x0014018C ([view code](security.c))
- [ ] Unhandled exception and NULL pointer dereference in control dispatching ([view code](main.c))
- [ ] Device creation with weak permissions ([view code](main.c))

Authors:

- 2026 - Herman Semenoff <<GermanAizek@yandex.ru>> ([germanaizek.github.io](https://germanaizek.github.io))
- Microsoft Corporation <<secure@microsoft.com>>
