---
title: "Exploiting pmxdrv.sys (Part 3): Finding Windows-Described Physical Memory"
description: "Using Windows' physical-memory resource map to identify scan ranges"
date: 2026-09-25 23:30:00 +0800
categories: [Research, Windows]
tags: [drivers, pmxdrv.sys, physical memory]
---

## Context

In [Part 2](https://3ggspl01t.github.io/posts/pmxdrv-poc2-part-2/), we got clarity over our `EPROCESS` search pipeline and were ready to move on to identifying SYSTEM process and our PoC process. But wait, we haven't touch on the part before the `EPROCESS` search pipeline. How do we know which physical addresses to scan for `Proc` allocations in the first place?

## Windows Hardware Resource Map

The entire physical address space (or the entire RAM) doesn't just contain physical memory, it is scattered with reserved regions and memory-mapped I/O (MMIO) used by hardware devices. Blindly walking the entire physical address space is unnecessary and potentially unsafe. Before scanning for process objects, we first needed to determine which physical address ranges Windows actually described as system physical memory (a.k.a Windows-described physical memory). Windows exposes this information through its hardware resource map, `HKEY_LOCAL_MACHINE\HARDWARE\RESOURCEMAP\System Resources\Physical Memory\.Translated`.

The `.Translated` value is stored as a Windows resource list. At a high level, it begins with a [`CM_RESOURCE_LIST`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_resource_list), which contains one or more [`CM_FULL_RESOURCE_DESCRIPTOR`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_full_resource_descriptor) structures. Each full descriptor contains a [`CM_PARTIAL_RESOURCE_LIST`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_partial_resource_list), which in turn contains an array of [`CM_PARTIAL_RESOURCE_DESCRIPTOR`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_partial_resource_descriptor) structures describing individual hardware resources.

```text
CM_RESOURCE_LIST
    │
    ├── CM_FULL_RESOURCE_DESCRIPTOR[0]
    │     │
    │     └── CM_PARTIAL_RESOURCE_LIST
    │           │
    │           ├── CM_PARTIAL_RESOURCE_DESCRIPTOR[0]
    │           ├── CM_PARTIAL_RESOURCE_DESCRIPTOR[1]
    │           ├── CM_PARTIAL_RESOURCE_DESCRIPTOR[2]
    │           └── ...
    │
    ├── CM_FULL_RESOURCE_DESCRIPTOR[1]
    │     │
    │     └── CM_PARTIAL_RESOURCE_LIST
    │           │
    │           ├── CM_PARTIAL_RESOURCE_DESCRIPTOR[0]
    │           ├── CM_PARTIAL_RESOURCE_DESCRIPTOR[1]
    │           ├── CM_PARTIAL_RESOURCE_DESCRIPTOR[2]
    │           └── ...
    │
    └── ...
```

## Memory Descriptors

Among the partial resource descriptors, we are interested only in descriptors whose `Type` identifies a memory resource: `CmResourceTypeMemory` or `CmResourceTypeMemoryLarge`. For each of such memory descriptor, its `Start` field and `Length` field identifies one Windows-described physical memory range. The fields relevant to our PoC appear at the following offsets in the resource list:

```text
.Translated registry value
│
├─ +0x00  CM_RESOURCE_LIST.Count
│
├─ +0x10  CM_PARTIAL_RESOURCE_LIST.Count
│
├─ +0x14  CM_PARTIAL_RESOURCE_DESCRIPTOR[0]
│      │
│      ├─ +0x00  first 4 bytes
│      │          ├─ +0x00  Type
│      │          ├─ +0x01  ShareDisposition
│      │          └─ +0x02  Flags
│      │
│      ├─ +0x04  Start
│      └─ +0x0C  Length
│
├─ +0x28  CM_PARTIAL_RESOURCE_DESCRIPTOR[1]
│      └─ ...
│
├─ +0x3C  CM_PARTIAL_RESOURCE_DESCRIPTOR[2]
│      └─ ...
│
└─ ...
```

Each `CM_PARTIAL_RESOURCE_DESCRIPTOR` occupies 0x14 bytes in this layout, so once the first descriptor is located at offset 0x14, the PoC can walk the array using increments of 0x14 bytes.


## Finding Windows-described Physical Memory

Translating the above concepts into a piece of code, we attempt to find windows-described physical memory.

```cpp
#include <windows.h>
#include <stdio.h>
#include <algorithm>
#include <vector>

#define PAGE_SIZE_BYTES               0x1000ULL
#define CM_RESOURCE_TYPE_MEMORY       3
#define CM_RESOURCE_TYPE_MEMORY_LARGE 7
#define RESOURCE_LIST_HEADER_SIZE     0x14
#define RESOURCE_DESCRIPTOR_SIZE      0x14

typedef struct _PHYSICAL_RANGE {
    UINT64 Start;
    UINT64 Length;
} PHYSICAL_RANGE;

// Safely reads an 8-byte UINT64 from a byte buffer using memcpy.
// It is mainly used while interpreting raw physical-memory data as EPROCESS fields.
static UINT64 ReadU64(const BYTE* p)
{
    UINT64 value = 0;
    memcpy(&value, p, sizeof(value));
    return value;
}

// Same idea as ReadU64(), but reads a 4-byte DWORD.
// It is used for things such as pool headers, pool tags, and ResourceMap fields.
static DWORD ReadU32(const BYTE* p)
{
    DWORD value = 0;
    memcpy(&value, p, sizeof(value));
    return value;
}

static BOOL LoadPhysicalMemoryRanges(std::vector<PHYSICAL_RANGE>* ranges)
{
    if (!ranges)
        return FALSE;

    ranges->clear();

    HKEY key = NULL;

    // Open Windows hardware resource map
    LSTATUS status = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
        0,
        KEY_QUERY_VALUE,
        &key);

    if (status != ERROR_SUCCESS) {
        printf("[-] RegOpenKeyExA for the physical memory map failed (%ld)\n", (long)status);
        return FALSE;
    }

    DWORD type = 0;
    DWORD size = 0;

    // Check size of the data
    status = RegQueryValueExA(
        key,
        ".Translated",
        NULL,
        &type,
        NULL,
        &size);

    if (status != ERROR_SUCCESS || type != REG_RESOURCE_LIST || size < RESOURCE_LIST_HEADER_SIZE) {
        printf("[-] Physical memory resource-list metadata is invalid\n");
        RegCloseKey(key);
        return FALSE;
    }

    // Allocate enough memory to hold data
    std::vector<BYTE> data(size);

    // Read .Translated
    status = RegQueryValueExA(
        key,
        ".Translated",
        NULL,
        &type,
        data.data(),
        &size);
    RegCloseKey(key);

    if (status != ERROR_SUCCESS || type != REG_RESOURCE_LIST ||
        size < RESOURCE_LIST_HEADER_SIZE) {
        printf("[-] Reading the physical memory resource list failed (%ld)\n", (long)status);
        return FALSE;
    }

    // Extract relevant fields from Windows resource structures
    DWORD resourceGroupCount = ReadU32(data.data()); // CM_RESOURCE_LIST.Count
    DWORD resourceDescriptorCount = ReadU32(data.data() + 0x10); // CM_PARTIAL_RESOURCE_LIST.Count

    if (resourceGroupCount != 1 || resourceDescriptorCount == 0 ||
        resourceDescriptorCount > (size - RESOURCE_LIST_HEADER_SIZE) / RESOURCE_DESCRIPTOR_SIZE) {
        printf("[-] Unexpected physical memory resource-list layout\n");
        return FALSE;
    }

    // Parse each CM_PARTIAL_RESOURCE_DESCRIPTOR entry
    for (DWORD i = 0; i < resourceDescriptorCount; i++) {
        const BYTE* descriptor = data.data() + RESOURCE_LIST_HEADER_SIZE + ((SIZE_T)i * RESOURCE_DESCRIPTOR_SIZE);

        // Identify the descriptors that represent memory
        DWORD header = ReadU32(descriptor);
        BYTE resourceType = (BYTE)(header & 0xFF);

        if (resourceType != CM_RESOURCE_TYPE_MEMORY && resourceType != CM_RESOURCE_TYPE_MEMORY_LARGE) {
            continue;
        }

        // Extract Start and Length of memory region
        UINT64 start = ReadU64(descriptor + 4);
        UINT64 length = ReadU64(descriptor + 0x0C);

        // Decodes large-memory encodings
        if ((header & 0xFF000000UL) != 0) {
            if (length > (UINT64_MAX >> 8)) {
                printf("[-] Overflow decoding a physical memory range\n");
                return FALSE;
            }
            length <<= 8;
        }

        // Checks for:
        // 1) empty ranges
        // 2) arithmetic that overflows 64-bit address
        // 3) Start not aligned to 4-KB page boundaries
        // 4) length not aligned to 4-KB page boundaries
        if (length == 0 || start > UINT64_MAX - (length - 1) ||
            (start & (PAGE_SIZE_BYTES - 1)) != 0 ||
            (length & (PAGE_SIZE_BYTES - 1)) != 0) {
            printf("[-] Invalid physical memory range in resource list\n");
            return FALSE;
        }

        // Save valid physical memory range
        PHYSICAL_RANGE range = {};
        range.Start = start;
        range.Length = length;
        ranges->push_back(range);
    }

    if (ranges->empty()) {
        printf("[-] No RAM ranges were present in the resource list\n");
        return FALSE;
    }

    // Sort ranges
    std::sort(
        ranges->begin(),
        ranges->end(),
        [](const PHYSICAL_RANGE& left, const PHYSICAL_RANGE& right) {
            return left.Start < right.Start;
        });

    // Print all physical memory ranges
    printf("[*] Physical RAM ranges from Windows ResourceMap:\n");
    UINT64 totalBytes = 0;

    for (SIZE_T i = 0; i < ranges->size(); i++) {
        const PHYSICAL_RANGE& range = (*ranges)[i];
        printf("    [%zu] 0x%016llX - 0x%016llX  (%llu MiB)\n",
            i,
            (unsigned long long)range.Start,
            (unsigned long long)(range.Start + range.Length - 1),
            (unsigned long long)(range.Length / (1024ULL * 1024ULL)));

        if (totalBytes <= UINT64_MAX - range.Length)
            totalBytes += range.Length;
    }

    printf("    Total described RAM: %llu MiB\n\n", (unsigned long long)(totalBytes / (1024ULL * 1024ULL)));
    return TRUE;
}

int main(int argc, char** argv)
{
    std::vector<PHYSICAL_RANGE> ranges;
    if (!LoadPhysicalMemoryRanges(&ranges)) {
        printf("[-] Fail to load physical memory range\n");
        return 1;
    }
}
```

On my Windows 10 build 19045 laptop with 32GB RAM, parsing the resource list produced four ranges.

![alt](/assets/img/posts/pmxdrv-poc2-part-3/loadphysicalmemoryranges.png)
_Windows-described physical memory ranges in Windows 10 build 19045 with 32GB RAM_

## What's Next?

Now that we know the physical memory ranges to scan for `Proc` allocations, we can test the EPROCESS discovery logic before continuing to find SYSTEM process and our PoC process.

To be continued...
