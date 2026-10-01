---
title: "Exploiting pmxdrv.sys (Part 5): Completing PoC #2"
description: "Correlating the final EPROCESS targets, replacing the parent process token, and putting everything togather"
date: 2026-10-01 14:15:00 +0800
categories: [Research, Windows]
tags: [drivers, pmxdrv.sys]
---

## Context

In [Part 4](/posts/pmxdrv-poc2-part-4/), we put the scanner together. It walked the physical memory ranges described by Windows in [Part 3](/posts/pmxdrv-poc2-part-3/), looked for `Proc` allocations, and collected `EPROCESS` candidates that passed the validation checks from [Part 2](/posts/pmxdrv-poc2-part-2/). The output included both `SYSTEM` and the PoC process.

Finding those objects was quite a tough journey, but the privilege escalation demonstration was not yet complete. PoC #2 still needed to choose the right process objects and use the physical write primitive to show the security impact of `pmxdrv.sys`.

This final post closes that loop. The completed PoC #2 resolves two process objects from the scan output, copies the `SYSTEM` process's token into the target process's `EPROCESS.Token` field, reads that field back, and leaves us with a console in which we can check the result.

## A Small Change to the Original Plan

In [Part 1](/posts/pmxdrv-poc2-part-1/), I described replacing the PoC process's token and spawning a child command prompt. The completed PoC #2 takes a slightly different route by targeting the PoC's parent process. 

The reason is purely to make the final demonstration clearer. I wanted the demonstration to be such that when PoC #2 exits, running `whoami` in the same command prompt that launched PoC #2 returns `nt authority\system`.

```text
Command prompt (parent)
    |
    +-- pmxdrv_poc2.exe (child)
           |
           +-- finds the parent's EPROCESS in physical memory
           +-- replaces the parent's EPROCESS.Token

Command prompt (now carrying the SYSTEM token)
    |
    +-- whoami
```

![alt](/assets/img/posts/pmxdrv-poc2-part-5/poc_launch.png)
_The command prompt that launches the PoC is the target process for the token replacement_

PoC #2 obtains its parent PID by taking a process snapshot and locating the entry for its own PID, whose `th32ParentProcessID` identifies the parent. It then locates that parent PID in the same snapshot and records its executable name from `szExeFile` for correlation with the scanned `EPROCESS` candidates.

## Resolving Targets to EPROCESS Physical Address

The scanner from Part 4 produces a list of validated `EPROCESS` candidates. From this list, `ResolveSystemAndParentTargets()` looks for candidates whose PID and image names match those of `SYSTEM` and the PoC's parent process.

| Target         | Correlation used by the PoC                                  |
| -------------- | ------------------------------------------------------------ |
| `SYSTEM`       | PID 4 and image name "System"                                |
| Parent process | Parent PID and image name obtained from the process snapshot |

The parent image name is truncated to fit the 15-byte `EPROCESS.ImageFileName` field, including space for the terminating `\0`, before the comparison. The name comparison is case-insensitive. PoC #2 requires **exactly one** match for each target and rejects a result in which both targets point to the same physical `EPROCESS` address. If the scan is incomplete or either match is absent or ambiguous, it exits without writing to physical memory.

```text
Validated EPROCESS candidates
          |
          +-- PID 4 + "System" --------------> SYSTEM EPROCESS PA
          |
          +-- parent PID + parent image ------> parent EPROCESS PA
```

The physical addresses are the important output here. Earlier posts established how to find plausible process objects; this stage turns those findings into the two addresses needed for the final stage.

![alt](/assets/img/posts/pmxdrv-poc2-part-5/target_resolution.png)
_Resolving targets to EPROCESS physical address_

## The Token Field Is an `EX_FAST_REF`

The field we want to change is `EPROCESS.Token`. On Windows 10 build 19045, PoC #2 uses the build-specific `+0x4B8` offset established earlier in the series. Its value is an `EX_FAST_REF`: the pointer portion references the token object, while the low four bits are used for cached reference information.

For the parent process, the physical address of the field is the parent `EPROCESS` physical address + 0x4B8. PoC #2 writes the eight-byte token reference captured from the `SYSTEM` candidate to that address through the driver's physical memory write primitive, and then reads the field back. Since the low reference bits may change, verification compares the token **pointer** portions of the written and read-back values, rather than requiring all eight bytes to remain identical.

```text
SYSTEM EPROCESS.Token  ---- copy reference ---->  parent EPROCESS.Token
                                                    |
                                                    +-- read-back
                                                    +-- compare token pointers
```

If the write call fails, PoC #2 reports failure. If the write was attempted but the read-back or pointer comparison fails, it attempts to restore the parent's token value saved from the scan and reports whether that restoration could be verified. A successful pointer comparison is reported as a verified token overwrite.

![alt](/assets/img/posts/pmxdrv-poc2-part-5/token_overwrite.png)
_The final stage writes the parent process's token field and checks the token pointer read back from physical memory_

## Putting Everything Together

The completed PoC #2 follows this sequence:

1. Check that the host is Windows 10 build 19045
2. Identify the PoC's parent process from a process snapshot
3. Open `\\.\PMXDRV` and confirm that the physical read primitive works
4. Load the Windows-described physical memory ranges from the `ResourceMap`
5. Scan those ranges and collect validated `EPROCESS` candidates
6. Correlate the unique `SYSTEM` and parent candidates by PID and image name
7. Overwrite the parent's token reference and verify its pointer by reading it back

The scan is intentionally strict: if any pages fail to read, it reports an incomplete scan and stops before target selection. The token write is therefore reached only after the preceding stages have succeeded.

## Privilege Escalation Demonstration

The accompanying PoC #2 recording shows the completed run: the PoC reaches the token overwrite stage, reports verification, and the parent console is then used to check its identity with `whoami`, which returns `nt authority\system`.

![alt](/assets/img/posts/pmxdrv-poc2-part-5/whoami_system.png)
_`whoami` ran from the parent command prompt after PoC #2 exits_

That last line is the practical answer to the question from Part 1. The driver exposed a physical memory read/write primitive. PoC #2 used it to find process objects and change the security context of a process already under our control.

<div style="width: 100%;">
{% include embed/video.html
  src='/assets/video/posts/pmxdrv-poc2-part-5/pmxdrv_poc2.mp4'
  title='PoC #2 Demo'
%}
</div>

## Conclusion

This series started with an undocumented IOCTL and a packed request structure. PoC #1 showed that `pmxdrv.sys` could map physical memory into user mode and perform reads and writes to it. For PoC #2, we worked through the extra pieces needed to turn that primitive into a tangible privilege escalation workflow: Windows-described physical memory ranges, `Proc` allocations, `EPROCESS` validation, process correlation, and finally the token overwrite.

The result is a working demonstration on the tested Windows 10 build 19045 environment: the parent process's token reference is replaced with `SYSTEM`'s, and the existing console runs `whoami` as `nt authority\system`. The exact structure offsets and memory-layout assumptions are specific to that build, while the larger lesson is broader: exposing arbitrary physical memory access to an unprivileged caller can cross the boundary between reading system state and changing the security context of a process.
