---
title: "Exploiting pmxdrv.sys (Part 2): Finding EPROCESS Reliably"
description: "Adapting an existing physical-memory process discovery strategy to Windows 10 build 19045"
date: 2026-09-18 23:00:00 +0800
categories: [Research, Windows]
tags: [drivers, pmxdrv.sys]
---

## Context

In [Part 1](https://3ggspl01t.github.io/posts/pmxdrv-poc2-part-1/), we got some clarity on the pieces needed to turn the physical-memory read/write primitive exposed by `pmxdrv.sys` into something tangible. Next, we find ways to reliably locate `EPROCESS` structures from physical memory.

## Inspiration from Existing PoC

While researching how other physical memory exploits solved this problem, I came across [h0mbre's CVE-2020-12138 exploit for atillk64.sys](https://h0mbre.github.io/atillk64_exploit/). The vulnerable driver was different, but the exploitation strategy stood out. h0mbre also had a primitive that allowed physical memory to be mapped into user space. From there, his PoC searched physical memory for Windows process allocations, located the corresponding `EPROCESS` structures, extracted process tokens, and ultimately replaced the PoC process's token with that of a privileged process.

That sounds like an ideal solution to what I wanted to do with `pmxdrv.sys`. The thing is our target environments aren't the same: h0mbre's was **Windows 10 build 18362** while mine was **Windows 10 build 19045**. So, we need to verify if the assumptions made and offsets used in h0mbre's PoC are still applicable to my target environment.

## h0mbre's Strategy

h0mbre's strategy for finding `EPROCESS` structures is summarised in the screenshot below:

![alt](/assets/img/posts/pmxdrv-poc2-part-2/h0mbre_eprocess_discovery_strategy.png)
_h0mbre's `EPROCESS` discovery strategy_

His observation of the layout between a pool header and EPROCESS on Windows 10 build 18362 can be simplified to:

```text
POOL_HEADER (aligned to 0x10)
    |
    | +0x4
    v
"Proc" pool tag
    |
    | between 0x20 and 0x90
    v
EPROCESS (starts with 0x00B80003)
```

Key observations include:

| Property                             | Observed value       |
| ------------------------------------ | ---------------------|
| Pool header alignment                | 0x10                 |
| `"Proc"` offset from pool header     | +0x4                 |
| Pool-header-to-EPROCESS displacement | between 0x20 and 0x90 |
| EPROCESS start value                 | 0x00B80003           |
| `_EPROCESS.UniqueProcessId`          | +0x2E8               |
| `_EPROCESS.Token`                    | +0x360               |
| `_EPROCESS.ImageFileName`            | +0x450               |

### The Aligned Pool Header and Consistent Proc Offset

The first two observations meant that instead of scanning every byte of physical memory for `"Proc"`, the PoC could inspect 0x10-aligned locations and check the four bytes into each location for 0x636F7250 (little-endian DWORD representing `Proc` in ASCII). This gave h0mbre a practical way to identify potential `Proc` allocations.

### The Variable Distance Between Pool Header and EPROCESS

From h0mbre's testing, he found that the distance between the start of `POOL_HEADER` and the start of `EPROCESS` was not constant; he observed it varying from 0x20 to 0x90. This meant that his PoC could not simply add a fixed offset to the `POOL_HEADER` to reach the `EPROCESS`. Instead, it needed to determine the displacement for each allocation. This observation turned out to be one of the most important parts of his methodology.

### The 0x00B80003 at the Start of EPROCESS

h0mbre also observed that the first four bytes of `EPROCESS` were `03 00 B8 00`. 

![alt](/assets/img/posts/pmxdrv-poc2-part-2/h0mbre_0x00b80003_marker.png)
_0x00B80003 at start of `EPROCESS` observed by h0mbre for build 18362_

This gave his PoC a convenient way to locate the start of `EPROCESS` by checking whether the DWORD at the displacements between 0x20 and 0x90 from `POOL_HEADER` is 0x00B80003. From there, the build-specific `EPROCESS` field offsets could be applied:

```text
EPROCESS + 0x2E8 -> UniqueProcessId
EPROCESS + 0x360 -> Token
EPROCESS + 0x450 -> ImageFileName
```

So, do these observations from build 18362 apply to build 19045?
To answer this, I went back to WinDbg to verify these observations through local kernel debugging.

## Verifying the Observations in Windows 10 Build 19045

List of observations to verify in build 19045:

1. Are process pool allocations still aligned on 0x10 boundaries?
2. Is the `Proc` tag still located at `POOL_HEADER + 0x4`?
3. What pool-header-to-`EPROCESS` displacements actually occur?
4. What does the beginning of `EPROCESS` look like on this build?
5. What are the relevant `EPROCESS` field offsets on build 19045?

The important part was to work from objects whose identity was already known.

Instead of finding something that looked like an `EPROCESS` and trying to prove that it was real, WinDbg could first give me a known-good process object.

I could then work backwards and inspect how that object was represented in its pool allocation.

### Confirm the EPROCESS Field Offsets

The next step was to determine where the fields required by the PoC existed inside `EPROCESS`.

![alt](/assets/img/posts/pmxdrv-poc2-part-2/eprocess_offsets.png)
_The three `EPROCESS` fields required by the PoC on Windows 10 build 19045_

This difference in offsets immediately showed why blindly copying h0mbre's PoC would fail.

| EPROCESS Field  | Offset in Build 19045 | Offset in Build 18362 |
| --------------- | --------------------- | --------------------- |
| UniqueProcessId | +0x440                | +0x2E8                |
| Token           | +0x4B8                | +0x360                |
| ImageFileName   | +0x5A8                | +0x450                |

Even though the `EPROCESS` field offsets are different, the exploitation strategy is still applicable.

### Locate Proc Allocations and Confirm Proc Tag Offset

Next, I ran the search for pool allocations containing `Proc` tag for 30 minutes. The pool headers returned were confirmed to be aligned on a 0x10 boundary and the `Proc` tags were confirmed to be +0x4 offset from the pool headers.

![alt](/assets/img/posts/pmxdrv-poc2-part-2/poolfind_proc.png)
_Pool allocations containing the `Proc` tag_

This meant that h0mbre's strategy of searching the physical memory in increments of 0x10 for pool headers and searching for 0x636F7250 at +0x4 from pool header is applicable for build 19045. 

### Measuring the Pool-Header-to-EPROCESS Displacement

To measure the pool-header-to-EPROCESS displacement, I used a known-good reference: `SYSTEM` (PID 4). Taking the difference between the `SYSTEM` `EPROCESS` and the pool header for the `Proc` allocation containing the `SYSTEM` `EPROCESS`, the pool-header-to-EPROCESS displacement for `SYSTEM` worked out to be 0x40.

![alt](/assets/img/posts/pmxdrv-poc2-part-2/system_eprocess.png)
_Locating the `SYSTEM` `EPROCESS`_

![alt](/assets/img/posts/pmxdrv-poc2-part-2/system_pool_header.png)
_Locating the pool header for `Proc` allocation containing the `SYSTEM` `EPROCESS`_

![alt](/assets/img/posts/pmxdrv-poc2-part-2/system_pool-header-to-eprocess_displacement.png)
_Pool-Header-to-EPROCESS displacement for `SYSTEM`_
 
I repeated the same steps with lsass.exe and spoolsv.exe and found their pool-header-to-EPROCESS displacement to be different from `SYSTEM`: 0x80 for lsass.exe and 0x70 for spoolsv.exe.

![alt](/assets/img/posts/pmxdrv-poc2-part-2/lsass_spoolsv_pool-header-to-eprocess_displacement.png)
_Pool-Header-to-EPROCESS displacement for lsass.exe and spoolsv.exe_

Summarising the pool-header-to-EPROCESS displacement for a few more processes which I tested:

| Process | Pool-header-to-EPROCESS Displacement |
| --- | --- |
| System | +0x40 |
| lsass.exe | +0x80 |
| spoolsv.exe | +0x70 |
| csrss.exe | +0x70 |
| smss.exe | +0x40 |
| services.exe | +0x70 |
| winlogon.exe | +0x80 |
| wininit.exe | +0x80 |

This confirmed that the pool-header-to-EPROCESS displacement is not a constant value. Hence, h0mbre's strategy of testing a range of locations is applicable for build 19045.

### Finding the EPROCESS Start Value

h0mbre observed 0x00B80003 at the start of the `EPROCESS` structures in his target environment and used it as an `EPROCESS` start marker. However, the same marker could not be found for build 19045 when I dumped the content following the pool headers of the processes I tested on. Instead, I observed 0x00000003 consistently appearing at the start of each process's `EPROCESS` structure.

![alt](/assets/img/posts/pmxdrv-poc2-part-2/0x00000003_marker.png)
_0x00000003 at start of `EPROCESS` observed for build 19045_

When I read the ASCII content at the ImageFileName offset (+0x5a8) from the 0x00000003 markers, I could see the names of the processes. This confirmed that 0x00000003 was indeed the start of `EPROCESS`.

![alt](/assets/img/posts/pmxdrv-poc2-part-2/confirm_0x00000003.png)
_Reading Process names found at offset where ImageFileName lives_

At this point, we can still adopt h0mbre's strategy of looking for an `EPROCESS` start value at a range of locations after finding a `Proc` allocation. The difference is that we will be looking for 0x00000003 instead of 0x00B80003.

### What Does 0x00000003 Mean?

So what does 0x00000003 mean? I looked up the [Vergilius Project](https://www.vergiliusproject.com/), which documents the layouts of undocumented internal Windows kernel structures, including build-specific field offsets for structures such as `EPROCESS`.

For build 19045, at offset 0x0 of an `EPROCESS` structure, we have a `KPROCESS` structure called `Pcb` or Process Control Block.

![alt](/assets/img/posts/pmxdrv-poc2-part-2/eprocess_0x0.png)
_`KPROCESS` structure, `Pcb`, at 0x0 of `EPROCESS` structure_

Next, at offset 0x0 of a `KPROCESS` structure, we have a `DISPATCHER_HEADER` structure called `Header`.

![alt](/assets/img/posts/pmxdrv-poc2-part-2/kprocess_0x0.png)
_`DISPATCHER_HEADER` structure, `Header`, at 0x0 of `KPROCESS` structure_

When we inspect the layout of `DISPATCHER_HEADER` structure, we see the fields that occupy the first four bytes (or DWORD).

![alt](/assets/img/posts/pmxdrv-poc2-part-2/dispatcher_header_dword.png)
_Fields at first 4 bytes of `DISPATCHER_HEADER` structure_

For our observed value of 0x00000003, this means that:

```text
_EPROCESS
+0x000 Pcb : _KPROCESS
        |
        +0x000 Header : _DISPATCHER_HEADER
                |
                +0x000 Type       = 0x03
		+0x001 Signalling = 0
		+0x002 Size       = 0
		+0x003 Reserved1  = 0
				
```

According to [Geoff Chappell's research](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/ke/kobjects.htm?utm_source=chatgpt.com), `_KPROCESS.Header.Type` is `ProcessObject (3)` from the internal `KOBJECTS` enumeration. To be honest, I still don't know exactly what this means. Anyway, let's move on.

## Putting the WinDbg Verification Together

At this point, the WinDbg verification gave enough information to separate the parts of h0mbre's strategy that still applied from the parts that had to be changed for build 19045.

The key observations were:

| Property | Build 18362 | Build 19045 | Decision |
| --- | --- | --- | --- |
| Pool header alignment | 0x10 | 0x10 | Adopt |
| `Proc` offset from pool header | +0x4 | +0x4 | Adopt |
| Pool-header-to-EPROCESS displacement | 0x20 to 0x90 observed | 0x40 to 0x80 observed | Adopt concept |
| EPROCESS start value | 0x00B80003 | 0x00000003 | Adopt concept |
| `UniqueProcessId` | +0x2E8 | +0x440 | Replace |
| `Token` | +0x360 | +0x4B8 | Replace |
| `ImageFileName` | +0x450 | +0x5A8 | Replace |

The important takeaway was that the strategy remained applicable, but the actual values were build-specific. For build 19045, the `EPROCESS` discovery logic retains the following ideas from h0mbre's PoC:

```text
Scan pool allocations at 0x10 boundaries
        |
        v
Check for "Proc" at +0x4
        |
        v
Try multiple possible EPROCESS displacements
        |
        v
Look for a build-specific EPROCESS-start value
```

The significant change was in the final steps: h0mbre could make strong use of `0x00B80003`, whereas I observed `0x00000003` instead.

## Additional Validation Checks

Compared to 0x00B80003, 0x00000003 is less unique and can appear in memory sections unrelated to `EPROCESS`. While the observation is useful, using 0x00000003 solely as proof of an `EPROCESS` will likely create many false positives. Therefore, additional checks are required to validate that the 0x00000003 DWORD encountered is indeed the start of an `EPROCESS` structure.

Once a 0x00000003 DWORD is encountered, the idea is to read off the data at specific offsets from `EPROCESS` and check whether they resemble the corresponding `EPROCESS` fields at those offsets.

| Check | Offset from `EPROCESS` | `EPROCESS` Field | Validation |
| --- | --- | --- | --- |
| 1 | +0x440 | UniqueProcessId | Non-zero 32-bit-sized value |
| 2 | +0x448 | ActiveProcessLinks.Flink | An 8-byte aligned canonical x64 kernel virtual address |
| 3 | +0x450 | ActiveProcessLinks.Blink | An 8-byte aligned canonical x64 kernel virtual address |
| 4 | +0x4B8 | Token | Actual token pointer after removing low reference bits is a canonical x64 kernel virtual address |
| 5 | +0x5A8 | ImageFileName | Non-empty; contains printable ASCII characters |

### Check 1: Plausible UniqueProcessId

The candidate `UniqueProcessId` is read from `EPROCESS + 0x440`. Only values which fall within the expected PID range will be accepted. This filters plausible process ID from random 64-bit data as well as the Idle process, whose PID is zero.

### Check 2: Plausible ActiveProcessLinks.Flink

The first pointer in `ActiveProcessLinks` is interpreted as `Flink`. The candidate Flink is read from `EPROCESS + 0x448`. The value will be checked to determine whether it resembles a canonical x64 kernel virtual address (i.e. 0xFFFF8xxx xxxxxxxx). Additionally, it will be checked to determine whether it is 8-byte aligned. A valid `_LIST_ENTRY` should not contain an arbitrary user-space or malformed address.

![alt](/assets/img/posts/pmxdrv-poc2-part-2/activeprocesslinks_offsets.png)
_ActiveProcessLinks offsets in `EPROCESS`_

### Check 3: Plausible ActiveProcessLinks.Blink

The second pointer in `ActiveProcessLinks` is interpreted as `Blink` and the candidate Blink is read from `EPROCESS + 0x450`. The same checks applied to the candidate `Flink` are also applied to the candidate `Blink`.

### Check 4: Plausible Token Pointer

The candidate `Token` value is read from `EPROCESS + 0x4B8`. Since the field is an `EX_FAST_REF`, the low four reference-count bits must first be cleared to obtain the underlying Token pointer. On x64, this is done by masking the raw value with 0xFFFFFFFFFFFFFFF0. The resulting pointer is then checked to determine whether it represents a canonical x64 kernel virtual address.

### Check 5: Plausible ImageFileName

Finally, the candidate `ImageFileName` is read from `EPROCESS + 0x5A8`. The image name must not be empty and must contain printable ASCII characters. This is useful because, unlike many `EPROCESS` fields, `ImageFileName` contains recognizable ASCII data. Random physical memory will fail this check because the candidate bytes contain zeros, binary data, or non-printable characters.

## The Revised EPROCESS Search Pipeline

With the inclusion of candidate validation checks, the complete `EPROCESS` search pipeline becomes:

```text
0x10-aligned pool location
          |
          v
   +0x4 == "Proc"?
          |
         yes
          |
          v
try EPROCESS displacement
   0x40 .. 0x80
          |
          v
candidate DWORD == 0x00000003?
       /      \
     no        yes
     |          |
     v          v
  reject      read fields
                  |
       +----------+----------+----------+----------+
       |          |          |          |          |
       v          v          v          v          v
      PID       Flink      Blink      Token      Image
       |          |          |          |          |
       v          v          v          v          v
   plausible?  kernel?    kernel?    kernel?    printable?
       |          |          |          |          |
       +----------+----------+----------+----------+
                             |
                             v
                       all five pass?
                          /       \
                        no         yes
                        |           |
                        v           v
                     reject       accept
```

The `0x00000003` value is deliberately outside the five validation checks because it serves as a pre-filter. The actual acceptance decision requires all five validation checks to succeed.

## Conclusion

h0mbre's atillk64.sys PoC provided a useful blueprint for turning physical memory access into privilege escalation via token stealing. However, directly copying the PoC would not have worked on Windows 10 build 19045. The WinDbg verification showed that some properties remained the same while others changed. More importantly, the 0x00000003 `EPROCESS` start value was much less distinctive than h0mbre's 0x00B80003, which changes how the marker can be used. Instead of treating it as proof of an `EPROCESS`, the PoC uses it as an inexpensive pre-filter before performing five additional validation checks.

The `EPROCESS` discovery strategy therefore became:

```text
Proc pool allocation
        |
        v
bounded displacement search
        |
        v
0x00000003 pre-filter
        |
        v
validate EPROCESS fields
        |
        v
accept only if all checks pass
```

This provides a more reliable way to identify `EPROCESS` structures from physical memory on the build 19045 target. With the process discovery logic established, the next step is to identify the `SYSTEM` process and a process under our control, recover their tokens, and use the physical write primitive for privilege escalation.

To be continued...
