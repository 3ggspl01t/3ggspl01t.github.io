---
title: "From Intel-SA-00086 Detection Tool to Physical Memory: Reverse Engineering pmxdrv.sys"
description: "Investigating whether a 2010 Intel PMx driver exposes dangerous kernel primitives"
date: 2026-08-05 18:40:00 +0800
categories: [Research, Windows]
tags: [reverse-engineering, drivers, pmxdrv.sys]
---

```
Filename: pmxdrv.sys
Hash: 82b30461dbf40ac15fce6a83b9bad2ebd05b27dea1b784eaa096422fe8927b7b (SHA256)
Version: 2010
Vendor: Intel
Architecture: x64
Goal: Determine whether it exposes arbitrary physical memory access
```

## Context
While investigating a Windows host, I came across Intel's [Intel-SA-00086](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00086.html) detection tool. Executing the tool also installs Intel's PMx driver, `pmxdrv.sys`. A quick search revealed that `pmxdrv.sys` is listed on [LOLDrivers](https://www.loldrivers.io/drivers/95fc9bf0-ec86-44b3-abad-a4c922aa7742/) as a known vulnerable driver.

![alt](/assets/img/posts/reverse-engineering-pmxdrv/loldrivers.png)
_`pmxdrv.sys` listed in LOLDrivers as a vulnerable Windows kernel driver_

However, the version installed on the Windows host was dated 2010, while the version referenced by LOLDrivers was from 2019. This raised an interesting question: is the 2010 version of `pmxdrv.sys` also vulnerable? This article documents my reverse engineering journey to answer that question.


## Background Concepts
Before we dive into the code, the following concepts provide the background needed to understand the rest of the post.

**Kernel vs. user space.** There are two privilege levels in Windows. Everyday applications, such as your browser or Notepad, run in **user space** where they are restricted from accessing sensitive parts of the system. Device drivers run in **kernel space** where they have full control over memory and hardware. Since drivers run with these privileges, they are a valuable target for attackers. If a vulnerable driver accepts unsafe requests from user-space applications, it can (unintentionally) grant them kernel-level access.

**Physical vs. virtual memory.** Programs use **virtual memory**, where the addresses they see are translated by the operating system and CPU into **physical memory** behind the scenes. This abstraction isolates processes and protects the kernel from direct access. A driver that can read or write arbitrary physical memory bypasses these protections because it operates beneath the virtual memory layer. It can access the memory of any process, as well as the kernel itself. **This is the capability we are looking for.**

**Device objects.** To communicate with user-space applications, a driver creates a device object (e.g `\Device\Pmxdrv`) and exposes it through a symbolic link (e.g. `\DosDevices\PMXDRV`). Applications can open the device using the standard `CreateFile` API (e.g. `\\.\PMXDRV`) which provides the entry point into the driver.

**IOCTLs.** After opening the device, an application communicates with the driver by sending **I/O control codes (IOCTLs)**. An IOCTL consists of a 32-bit control code (and an optional data buffer) which tells the driver which operation to perform. Together, a driver's IOCTLs form its public interface.

**Access control.** Like files, device objects have permissions (security descriptors) that determine who can open them. If access is restricted to administrators, the risk is reduced. However, if any user can open the device, then any application can interact with the driver's privileged functionality.

**Putting it together:** A vulnerable driver becomes dangerous when it combines an accessible interface with powerful functionality. In this case, we are looking for two things: a device that ordinary users can open, and an IOCTL that exposes privileged operations such as reading or writing physical memory. If such a combination exists, a low-privileged application may be able to cross the user/kernel boundary and gain control over the operating system.

Let's open `pmxdrv.sys` and see whether the above-mentioned conditions are present.

## Inspecting the Imports

After opening the driver file in IDA, we first look at the functions (or kernel APIs) imported as they provide clues to the driver's capabilities. A driver cannot access physical memory, communicate with hardware, or interact with other processes without calling specific kernel APIs to perform those actions.

Some imports should immediately stand out:

| If you see...                                              | It suggests...                                               |
| ---------------------------------------------------------- | ------------------------------------------------------------ |
| `MmMapIoSpace`                                             | Mapping physical memory (device/IO ranges)                   |
| `ZwOpenSection` + `ZwMapViewOfSection`                     | Mapping a section object — possibly `\Device\PhysicalMemory` |
| `MmGetPhysicalAddress`, `MmAllocateContiguousMemory`       | Physical-address work                                        |
| `IoAllocateMdl`, `MmProbeAndLockPages`                     | Direct access to locked physical pages                       |
| `HalGetBusDataByOffset`, `HalSetBusDataByOffset`           | PCI configuration space read/write                           |
| `__readmsr` / `__writemsr` (often intrinsics, not imports) | CPU model-specific registers                                 |
| `ZwOpenProcess`, `PsLookupProcessByProcessId`              | Reaching into other processes                                |

In the case of `pmxdrv.sys`, the combination of `ZwOpenSection` and `ZwMapViewOfSection` stand out as they are used when a driver needs to map a section object into its address space. One possible target is `\Device\PhysicalMemory` — a special kernel object representing the system's physical memory.

![alt](/assets/img/posts/reverse-engineering-pmxdrv/imports.png)
_Functions imported by `pmxdrv.sys` suggesting interaction with physical memory and hardware resources._

At this stage, the imports strongly suggest that `pmxdrv.sys` is capable of interacting with physical memory. The next question is where these capabilities are exposed. To answer that, we first need to identify the driver's entry point and understand how it initializes itself.

> **Note**: Treat early observations as hypotheses so as to identify interesting areas worth investigating.

## Finding DriverEntry

Every Windows driver exports a `DriverEntry` function, which the operating system calls when the driver is loaded. This is where the driver performs its initialization, such as creating device objects and registering its dispatch functions. Opening the entry point in IDA initially appears promising, but a closer look reveals something unexpected:

![alt](/assets/img/posts/reverse-engineering-pmxdrv/gsdriverentry.png)
_`GsDriverEntry` initializes the stack security cookie before transferring execution to the driver's real entry point._

Despite being identified as the entry point by IDA, this function did not contain any driver-specific logic. Instead, it is a compiler-generated stub responsible for initializing the kernel stack security cookie before transferring control to the real initialization routine. This function is the `GsDriverEntry` which is automatically added by the compiler when the `/GS` (buffer security check) build flag is active.

Indicators that supported this:
- The constant `0x2B992DDFA232` is the default stack cookie value generated by the Microsoft Visual C++ compiler.
- The read from `0xFFFFF78000000320` accesses `KUSER_SHARED_DATA`, a kernel structure used to introduce runtime randomness into the cookie.
- The function finishes by calling `sub_11940()`, passing the original `PDRIVER_OBJECT`.

These strongly suggest that `sub_11940()` contains the driver's actual initialization logic.

> **Note**: Renamed `sub_1A008()` to `GsDriverEntry` and `sub_11940()` to `DriverEntry` to facilitate following.

Following into `DriverEntry` reveals the driver's initialization logic.

## Identifying the device object

`DriverEntry` first creates the driver's device object. It calls `IoCreateDevice` to create `\Device\Pmxdrv`, followed by `IoCreateSymbolicLink` to expose it as `\DosDevices\PMXDRV`. This symbolic link allows a user-mode application to open the driver using the standard `CreateFile` API `\\.\PMXDRV`. Obtaining this handle is the first step to communicating with the driver.

![alt](/assets/img/posts/reverse-engineering-pmxdrv/device_object_creation.png)
_`DriverEntry` creates the device object and exposes it through the `\\.\PMXDRV` symbolic link._

Interestingly, the driver uses the standard `IoCreateDevice` API instead of `IoCreateDeviceSecure`, and it does not provide an explicit security descriptor. As a result, the driver leaves access control to the default device permissions assigned by Windows. At this stage, we still do not know whether those defaults make the driver reachable by unprivileged users.

## Analysing the dispatch table

After creating its device object, `DriverEntry` registers the dispatch functions responsible for handling requests from user space.

Windows communicates with drivers using I/O Request Packets (IRPs). Each IRP type is associated with a function pointer stored in the driver's `MajorFunction` dispatch table. During initialization, `pmxdrv.sys` populates this table with the handlers it wishes to expose:

![alt](/assets/img/posts/reverse-engineering-pmxdrv/dispatch_table.png)
_Registration of driver dispatch functions._

Of interest is `IRP_MJ_DEVICE_CONTROL` (index 14) as every IOCTL issued by a user-mode application is processed by this dispatch function, making it the gateway to the driver's functionality.

> **Note**: Renamed `sub_11800()` to `DispatchDeviceControl` to facilitate following.

## Enumerating the IOCTLs

`DispatchDeviceControl` extracts the following parameters from the incoming I/O Request Packet (IRP) and passes them to `sub_114D0()`:
- the IOCTL control code, `Irp->IoControlCode`
- `Irp->AssociatedIrp.SystemBuffer` and `Irp->InputBufferLength` which contains the caller's input buffer and buffer length respectively
- `Irp->UserBuffer` and `Irp->OutputBufferLength` which contains the caller's output buffer and buffer length respectively.

![alt](/assets/img/posts/reverse-engineering-pmxdrv/dispatchdevicecontrol.png)
_`DispatchDeviceControl` extracts the IOCTL request from the IRP before passing to `sub_114D0`._

> **Note**: Renamed `sub_114D0()` to `DispatchIoctlHandler` to facilitate following.

Inside `DispatchIoctlHandler` is a large switch statement that dispatches requests based on the IOCTL code supplied by the caller. The first case corresponds to `0x00222A80`, followed by `0x00222A84`, `0x00222A88`, and so on, increasing by four each time. This is effectively the driver's public interface with a total of 22 IOCTL handlers.

![alt](/assets/img/posts/reverse-engineering-pmxdrv/dispatchioctlhandler.png)
_The driver's IOCTL dispatcher exposes 22 vendor-defined control codes._

> **Note**: IDA displays the IOCTL codes in decimal. Converting them to hexadecimal facilitates following.

## Decoding the IOCTLs

Before examining what each IOCTL does, let's understand [how Windows constructs an IOCTL value](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes). Each IOCTL is a 32-bit value is constructed by combining four fields into a single integer:
```
CTL_CODE = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
```

To decode an IOCTL, reverse the process by extracting each field from its corresponding bits.

| Field |	Bits |	Extraction |
|---|---|---|
| DeviceType	| 16-31	| `(code >> 16) & 0xFFFF` |
| Access	| 14-15	| `(code >> 14) & 0x3` |
| Function	| 2-13	| `(code >> 2) & 0xFFF` |
| Method	| 0-1	| `code & 0x3` |

Applying this to the first IOCTL, `0x00222A80`, produces the following values:

| Field |	Value |	Meaning |
|---|---|---|
| DeviceType	| `0x22`	| `FILE_DEVICE_UNKNOWN` |
| Access	| `0`	| `FILE_ANY_ACCESS` |
| Function	| `0xAA0`	| Vendor-defined function |
| Method	| `0`	| `METHOD_BUFFERED` |

The **Access** field determines whether the Windows I/O Manager requires the caller to have read and/or write access when opening the device. `FILE_ANY_ACCESS` means the I/O Manager does not restrict callers from invoking the IOCTL.

The **Method** field determines how data is exchanged between user mode and the driver. `METHOD_BUFFERED` instructs the I/O Manager to copy the caller's input into `Irp->AssociatedIrp.SystemBuffer` before the driver processes the request. This is generally considered the safest transfer method because the driver works with a kernel-managed buffer instead of directly dereferencing user-space pointers.

Decoding the remaining 21 IOCTLs reveals that all of them uses the same combination, changing only the **Function** field:
- `FILE_DEVICE_UNKNOWN`
- `FILE_ANY_ACCESS`
- `METHOD_BUFFERED`

The next question is: which of these 22 IOCTLs leads to the physical memory APIs identified in the imports?

## Tracing the Physical Memory Handler

At this point, we know two things about `pmxdrv.sys`:
- the driver imports APIs commonly associated with physical memory operations, and
- it exposes 22 IOCTL handlers that can be reached through `IRP_MJ_DEVICE_CONTROL`.

Reading all 22 handlers would be time-consuming. Instead, we can use IDA's cross-reference feature (Xrefs to) on `ZwMapViewOfSection` to work backwards through the callers until we reach one or more of the IOCTL handlers in `DispatchIoctlHandler`.

Following the cross-references from `ZwmMapViewOfSection` leads to `sub_13B70` which is referenced by three of the 22 IOCTL handlers (`sub_14520`, `sub_12FD0` and `sub_132D0`), making it the next function worthy of closer inspection.

![alt](/assets/img/posts/reverse-engineering-pmxdrv/function_trace.png)
_Function call from `DispatchIoctlHandler` to `ZwMapViewOfSection`._

## Analysing MapPhysicalMemory (sub_13B70)

`sub_13B70` takes in three arguments:
- `RequestedPhysicalAddress`: the 64-bit physical address which the caller wants mapped.
- `PageCount`: the number of 4kB pages to map.
- `ppMappedAddress`: the pointer which the function will writes the resulting virtual address into.

![alt](/assets/img/posts/reverse-engineering-pmxdrv/sub_13b70_args.png)
_Arguments of `sub_13B70`._

The function first constructs the Unicode string `\Device\PhysicalMemory` and passes it to [`ZwOpenSection`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopensection) with the access mask `SECTION_ALL_ACCESS`. Instead of opening an ordinary file or device, the driver requests full access to the Windows kernel object representing the system's physical memory.

![alt](/assets/img/posts/reverse-engineering-pmxdrv/zwopensection.png)
_`sub_13B70` opens the `\Device\PhysicalMemory` section object with full access rights._

Once the section has been opened, the function calls [`ZwMapViewOfSection`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection) to map the requested region into memory. Several parameters are particularly significant:
- The target process is `(HANDLE)0xFFFFFFFFFFFFFFFF`, the Windows pseudo-handle representing the current process. This means the mapping is created directly within the address space of whichever process issued the IOCTL.
- The page protection is `PAGE_READWRITE`, allowing the mapped memory to be both read from and written to.
- The physical address (`RequestedPhysicalAddress`) supplied by the caller is passed directly to `ZwMapViewOfSection` as the section offset.

![alt](/assets/img/posts/reverse-engineering-pmxdrv/zwmapviewofsection.png)
_The requested physical memory is mapped directly into the calling process with read/write permissions._

Finally, the mapped address is returned through caller-supplied parameter `ppMappedAddress`. From the caller's perspective, the result is simply a normal pointer. No additional IOCTLs are required to access the mapped region; reads and writes are performed by directly dereferencing the returned address.

![alt](/assets/img/posts/reverse-engineering-pmxdrv/return_address.png)
_Mapped address returned to caller as a normal pointer._

At this stage, we found the primitive we were looking for. Through `sub_13B70`, a user-mode application can supply an arbitrary physical address, have the driver map that memory into its own address space with read/write permissions, and receive a pointer to the mapped region. Once the mapping exists, the application can freely read from or write to the corresponding physical memory without requiring additional IOCTLs.

The remaining question is whether this functionality can be reached from an unprivileged process through one of the driver's IOCTL handlers.

> **Note**: Renamed `sub_13B70` to `MapPhysicalMemory` to facilitate following.

## Assessing Reachability

During the analysis of `DriverEntry`, we observed that the driver creates its device object using `IoCreateDevice` without supplying an explicit security descriptor. While this suggests that access control is left to the operating system's defaults, the effective permissions can only be confirmed by examining the live device object.

After loading the driver on a live system, we use Sysinternals' AccessChk to inspect the device's security descriptor:

![alt](/assets/img/posts/reverse-engineering-pmxdrv/accesschk.png)
_AccessChk shows the effective security descriptor applied to `\Device\Pmxdrv`._

The output shows two permissions of particular interest:
- The device's discretionary access control list (DACL) grants read and write access to `Everyone`. Any user on the system can therefore obtain a handle to the device.
- The device carries a Low Mandatory Level integrity label with the No-Write-Up policy. Windows integrity levels provide an additional layer of access control, preventing lower-integrity processes from modifying higher-integrity objects. In this case, the label does not prevent ordinary user applications from opening the device. Processes running at Low, Medium or High integrity can all access it.

Collectively, these permissions reveal that the driver does not meaningfully restrict who can communicate with it. Any unprivileged user can open `\\.\PMXDRV` and issue IOCTL requests.

## Conclusion

This completes the picture.

Earlier in the investigation, the import analysis suggested that the driver might expose physical memory operations. Subsequent reverse engineering confirmed that three of its IOCTL handlers maps arbitrary physical memory into the caller's address space with read/write permissions. Finally, the device's security descriptor shows that this functionality is accessible by unprivileged users.

In other words, both conditions identified at the beginning of this article have now been satisfied:
- [x] The device is accessible from user mode.
- [x] The driver exposes a privileged operation through three IOCTL codes `0x222AB8`, `0x222AC8` and `0x222ACC`.

In theory, this makes the physical memory mapping functionality reachable by unprivileged applications, providing the primitive required for local privilege escalation.

Finally, we have reached a natural stopping point for this post. Next (hopefully) will be a POC to exploit `pmxdrv.sys`'s arbitrary physical memory read/write primitive.
