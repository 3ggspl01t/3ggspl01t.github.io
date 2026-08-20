---
title: "What Does pmxdrv.sys Expect? Reconstructing the IOCTL Input Structure"
description: "Tracing IOCTL 0x00222AB8 to uncover the undocumented request format"
date: 2026-08-12 16:15:00 +0800
categories: [Research, Windows]
tags: [reverse-engineering, drivers, pmxdrv.sys]
---

## Context

In the [previous post](https://3ggspl01t.github.io/posts/reverse-engineering-pmxdrv/), we identified 3 IOCTLs in `pmxdrv.sys` that eventually lead to a physical-memory mapping API, `ZwMapViewOfSection`.

The next natural step is to develop a Proof of Concept (PoC) to demonstrate how the driver can be used for privilege escalation. But in order to do that, we first need to understand what data the driver expects from the caller.

This post focuses solely on reconstructing the input buffers required by the `0x00222AB8` IOCTL. The actual PoC and validation of the primitive will be covered in the subsequent post(s).

## Reconstructing the Input Structure

Since IOCTL `0x00222AB8` has the shortest path to `ZwMapViewOfSection`, we will use this path to determine what data the driver expected from the caller.

![alt](/assets/img/posts/reconstruct-ioctl-input-structure/function_trace.png)
_Function trace from `DispatchIoctlHandler` to `ZwMapViewOfSection`._

The IOCTL handler, `sub_14520`, receives the caller's `SystemBuffer` through the `IOCTL_ARGS` structure. We follow `sub_14520` to see what it does with this buffer.

![alt](/assets/img/posts/reconstruct-ioctl-input-structure/0x222ab8.png)
_`DispatchIoctlHandler` routes IOCTL `0x00222AB8` to `sub_14520`._

`sub_14520` is split into 32-bit and 64-bit paths. Focusing on the 64-bit path, the `IOCTL_ARGS` structure is first passed to `sub_11290` along with the pointer to `pFlags` and `ppRequest` variables. We follow `sub_11290` to see what it does.

![alt](/assets/img/posts/reconstruct-ioctl-input-structure/args_passed_to_sub_11290.png)
_`IOCTL_ARGS` structure passed to `sub_11290()` inside `sub 14520`._

Similar to `sub_14520`, `sub_11290` is also split into 32-bit and 64-bit paths. Let's focus on 64-bit path.

![alt](/assets/img/posts/reconstruct-ioctl-input-structure/reconstruct_input_structure.png)
_64-bit path in `sub_11290()`._

The first check tells us that the driver expects a 16-byte input buffer. The next 3 lines reveal how those 16 bytes are interpreted.

- `*ppRequest = *SystemBuffer_1;`
  - `SystemBuffer_1` points to the start of the input buffer and is treated as an `__int64 *`. Therefore, line reads the first 8 bytes of the input buffer and stores them in `ppRequest`.
  
- `*((_DWORD *)SystemBuffer_1 + 2)`
  - Here, the pointer is treated as a `DWORD *`, meaning each increment represents 4 bytes:
   ```
   DWORD #0 → +0x00
   DWORD #1 → +0x04
   DWORD #2 → +0x08
   ```
  - Therefore, this line reads a 4-byte value at offset `+0x08` and stores it in `pFlag`.
  
- `v7 = *((_DWORD *)SystemBuffer_1 + 2) <= 0x3Fu;`
  - The same value is then checked against 0x3F (63). In short, the driver requires the flag value to be less than 63.

Simplifying the logic of `sub_11290`:

```c
if (InputBufferLength != 16)
    return 0;

request = *(UINT64 *)(SystemBuffer + 0x00);
flag    = *(DWORD *)(SystemBuffer + 0x08);

if (flag > 63)
    return 0;

return 1;
```

At this point, this is what we observed about the 16-byte input buffer:

| Offset from `SystemBuffer_1` | Size    | Observed use    |
| ---------------------------- | ------- | --------------- |
| `+0x00`                      | 8 bytes | Request pointer |
| `+0x08`                      | 4 bytes | Flag            |
| `+0x0C`                      | 4 bytes | Unknown         |

> **Note**: Although the driver requires a 16-byte input buffer, `sub_11290` does not access the last 4 bytes. Their purpose therefore remains unknown.

## Reconstructing the Request Structure

Returning from `sub_11290` to `sub_14520`, we now know that `ppRequest` contains the value extracted from offset +0x00 of the input buffer. From here, we see that the `ppRequest` pointer is used as a reference to read several values relative to it.

![alt](/assets/img/posts/reconstruct-ioctl-input-structure/reconstruct_request_structure.png)
_`ppRequest` pointer used as reference to read several values._

These lines alone were enough to make me see stars. Let's break them down and see what they do.

The first line checks that:
1. `ppRequest` is not empty.
2. The 4-byte value at `ppRequest` is exactly 24.
3. The 8-byte value at offset +0x04 from `ppRequest` is not empty.

The next line passes 3 values from the request to `MapPhysicalMemory`:
1. The 8-byte value at offset +0x04 from `ppRequest`.
2. The 4-byte value at offset +0x0c from `ppRequest`.
3. The pointer to the address at offset +0x10 from `ppRequest`.

Examining the function definition of `MapPhysicalMemory`, we can see the variables which receive the 3 values.

![alt](/assets/img/posts/reconstruct-ioctl-input-structure/mapphyiscalmemory_function_defintion.png)
_`Variables receiving the 3 values passed to `MapPhysicalMemory`._

This essentially means that:

| Offset from `ppRequest` | Size    | Observed use                            |
| ----------------------- | ------- | --------------------------------------- |
| `+0x04`                 | 8 bytes | Passed as the physical-address argument |
| `+0x0c`                 | 4 bytes | Passed as the page-count argument       |
| `+0x10`                 | 8 bytes | Address supplied as the output location |

If we include the 4-byte value which the first line expects to be 24, the structure of a valid request to `MapPhysicalMemory` is likely:

| Field             | Offset from `ppRequest` | Size    | Purpose                               |
| ----------------- | ----------------------- | ------- |
| `Size`            | +0x00                   | 4 bytes | Must contain 24                       |
| `PhysicalAddress` | +0x04                   | 8 bytes | Physical address to map               |
| `PageCount`       | +0x0c                   | 4 bytes | Number of pages to map                |
| `MappedAddress`   | +0x10                   | 8 bytes | Receives the resulting mapped address |

> **Note**: Since the total size of the request structure adds up to 24, the first field of the request structure is likely the structure size.

## Structures Required

At this point, the relationship between the 2 reconstructed structures are clear.

![alt](/assets/img/posts/reconstruct-ioctl-input-structure/structures_required.png)
_Relationship between INPUT_BUFFER and REQUEST structures._

During PoC development, we can represent the reconstructed layouts as the following C structures:

```c
typedef struct {
    DWORD  Size;             // +0x00, must be 24
    UINT64 PhysicalAddress;  // +0x04
    DWORD  PageCount;        // +0x0C
    UINT64 MappedAddress;    // +0x10, output
} REQUEST;

typedef struct {
    UINT64 Request;      // +0x00, points to REQUEST structure
    DWORD  Flag;         // +0x08, must be <= 63
    DWORD  Unknown;      // +0x0C
} INPUT_BUFFER;
```

## Conclusion

This reverse-engineering step gives us the information needed to construct a valid request for IOCTL `0x00222AB8`.

We now know that the IOCTL expects a 16-byte input buffer containing a pointer to a second request structure. We also know the layout of that request structure and how its fields are passed to the driver's physical-memory mapping routine.

The next step (hopefully) is to put this reconstructed format to the test and determine whether we can successfully obtain and access the mapped physical memory.
