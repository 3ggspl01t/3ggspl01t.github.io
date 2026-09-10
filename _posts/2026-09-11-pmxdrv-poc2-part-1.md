---
title: "Exploiting pmxdrv.sys (Part 1): Understanding the Pieces"
description: "Breaking down process tokens, pages, kernel pool, pool tags and EPROCESS"
date: 2026-09-11 00:00:00 +0800
categories: [Research, Windows]
tags: [drivers, pmxdrv.sys]
---

## Context

In the [previous post](https://3ggspl01t.github.io/posts/pmxdrv-poc1/), we saw that an unprivileged user could use the PMx driver to map arbitrary physical memory.

That established the primitive. However, a primitive by itself does not always make the security impact obvious. Saying "This driver lets a process map arbitrary physical memory." is very different from showing:

```text
C:\> whoami
nt authority\system
```

For the next stage, I wanted to answer a more practical question: Can the physical memory read/write primitive exposed by `pmxdrv.sys` be turned into local privilege escalation?

This post documents the development of PoC #2, which uses the arbitrary physical memory read/write primitive to locate Windows process objects in physical memory, replace the current process's access token with the `SYSTEM` token, and finally spawn a child command prompt running as `NT AUTHORITY\SYSTEM`.

## Where We Left Off

In PoC #1, we used `pmxdrv.sys` to map an arbitrary physical address to a user-mode virtual address. We then read data from that address and wrote test bytes to the same address, thereby demonstrating the arbitrary physical memory read/write primitive.

The same primitive can therefore be used to:
1. Locate interesting kernel objects
2. Modify their underlying physical pages

The difficult part is no longer accessing memory, but figuring out what to modify.

## The Target: Windows Process Tokens

Every Windows process runs under a particular security context. This determines who the process is acting as, which groups it belongs to, and what privileges it has. That security context is represented by an **access token**.

```text
Process
   │
   ▼
Access Token
   │
   ├── User identity
   ├── Group memberships
   ├── Privileges
   └── Integrity information
```

For example, a normal command prompt may run under the token of the currently logged-in user. In contrast, core Windows services commonly run under the highly privileged `NT AUTHORITY\SYSTEM` security context.

For PoC #2, the objective is to replace our current process's token with the token carried by the `SYSTEM` process. After that, any child process spawned by our current process inherits the `NT AUTHORITY\SYSTEM` security context.

```text
Before
------

Current EPROCESS                  SYSTEM EPROCESS
┌─────────────────┐              ┌─────────────────┐
│ PID             │              │ PID = 4         │
│                 │              │                 │
│ Token ───────┐  │              │ Token ───────┐  │
└──────────────│──┘              └──────────────│──┘
               │                                │
               ▼                                ▼
          User Token                       SYSTEM Token


After
-----

Current EPROCESS                  SYSTEM EPROCESS
┌─────────────────┐              ┌─────────────────┐
│ PID             │              │ PID = 4         │
│                 │              │                 │
│ Token ────────────────────────────────┐          │
└─────────────────┘              └──────│──────────┘
                                        │
                                        ▼
                                  SYSTEM Token
```

The next question is: Where does Windows keep a process's access token, and how can we locate it using only physical memory access?

But before looking at how we can find tokens in physical memory, it helps to establish a few Windows memory management concepts.

## Physical Memory and Pages

At the lowest level, a machine has **physical memory**: the actual RAM installed in the system. Windows does not manage this memory as one enormous continuous block. Instead, it divides memory into fixed-size units called **pages**. On 64-bit Windows, a normal page is typically **4 KB**.

## Kernel Pools

The Windows kernel frequently needs memory for objects whose lifespan cannot be determined in advance. This includes objects representing:
- processes
- files
- registry keys
- network state
- synchronization objects
- driver-specific data

As such, Windows maintains dynamically managed regions of kernel memory called **pools**. When the kernel needs memory for an object, it asks the pool allocator for a suitably sized chunk. When the object is no longer required, that chunk is returned and reused.

The important distinction is that a **page** is a unit of memory, whereas a **pool allocation** is an object or buffer placed within that memory. A page can therefore contain several pool allocations, depending on the size of those allocations.

## Pool Tags

Pool allocations are commonly associated with four-byte identifiers called **pool tags**, which help identify the type of allocation the memory belongs to. For example, the `Proc` pool tag is associated with process-related allocations. When examining physical memory, finding a `Proc` tag gives us a clue that a process object may be located nearby. That makes `Proc` a useful starting point for finding `EPROCESS` structures in memory.

However, a pool tag should be treated as a **candidate marker**, not definitive proof that a valid object has been found.

## EPROCESS

Windows uses `EPROCESS` structures to represent process objects in the kernel. An `EPROCESS` contains, directly or indirectly, information about a process such as:
- Process ID
- Process name
- Scheduling information
- Memory-management state
- Handles
- Security information
- Access token
- Many other fields

For PoC #2, three fields are especially useful:
1. `UniqueProcessId` tells us which process the structure belongs to.
2. `ImageFileName` provides the process name.
3. `Token` references the security token that determines the process's identity and privileges.

That last field is what makes `EPROCESS` especially juicy from a privilege escalation perspective. 

## Putting it all Together

The below diagram sums up the key Windows memory management concepts earlier and (hopefully) illustrates how the physical memory might look like:

```text
Physical memory
│
├── 4 KB Page
│   ├── ordinary data
│   └── free / unused space
│
├── 4 KB Page
│   └── kernel pool memory
│       ├── [File] allocation
│       ├── [Proc] allocation
│       │    └── EPROCESS
│       │         ├── UniqueProcessId
│       │         ├── ImageFileName
│       │         └── Token
│       └── padding / allocator metadata
│
├── 4 KB Page
│   └── kernel pool memory
│       ├── [....] other kernel allocation
│       └── [Proc] allocation
│            └── EPROCESS
│
├── 4 KB Page
│   └── file cache / other kernel data
│
└── ...
```

A useful analogy would be a warehouse:

| Windows memory concept | Warehouse analogy |
| --- | --- |
| Physical memory | The entire warehouse |
| Pages | Standard-sized pallets |
| Kernel pool | A section of the warehouse reserved for dynamically allocated kernel objects |
| Pool allocations | Boxes placed on pallets |
| Pool tags | Labels on the boxes |
| `EPROCESS` | Possible content of boxes labeled `Proc` |

## Strategy for PoC #2

At this point, we know that:
- the `SYSTEM` process has the token we want
- that token is referenced from the `SYSTEM` process's `EPROCESS`
- our own process has another `EPROCESS` containing its current token
- both structures ultimately reside somewhere in physical memory
- `pmxdrv.sys` allows us to read and modify that physical memory

Conceptually, we can escalate privileges by perfoming the following steps:
1. Find `SYSTEM`'s `EPROCESS`
2. Read `SYSTEM`'s `EPROCESS.Token`
3. Find our `EPROCESS`
4. Replace our `EPROCESS.Token`
5. Spawn `cmd.exe` as `NT AUTHORITY\SYSTEM`

## What's Next?

With the key Windows memory management concepts covered and the strategy for PoC #2 defined, the challenge now lies in turning these into something tangible. The next step is figuring out how to reliably locate the `SYSTEM` and current process `EPROCESS` structures in physical memory.

To be continued...
