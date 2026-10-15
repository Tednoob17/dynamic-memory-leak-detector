# Background: how memory allocation works on Linux

This page explains what happens between a call to `malloc` and the RAM it ends up using, and why that shapes dmld's design. It assumes basic C knowledge and no prior knowledge of allocators or of the kernel.

## Pages: how the kernel sees memory

Programs don't use physical RAM directly. They use virtual addresses, and the kernel maps them to physical memory in fixed-size blocks called **pages**, usually 4 KiB.

The kernel provides physical pages lazily. When a program reserves memory, nothing is placed in RAM yet. The first time the program touches an address in a page that isn't mapped, the CPU traps into the kernel. The kernel then maps a page, and the program resumes without noticing. That trap is a **page fault**:

- A **minor** fault is resolved without disk I/O, for example by handing out a fresh zeroed page. It is cheap.
- A **major** fault needs disk I/O, for example to read a page back from swap.[^perf-event] It is around a thousand times slower.

The kernel never deals in anything smaller than a page.

## The allocator sits between your code and the kernel

`malloc` and `free` aren't system calls. They are functions in a library, the **allocator**: glibc by default, or jemalloc, tcmalloc, mimalloc and others.

The allocator manages its own pool of memory. It requests large chunks from the kernel, then carves them up into the small blocks your program asks for:

```
Program :  malloc(32) malloc(64) malloc(32) free() malloc(16) ...   ← millions of calls
               │
Allocator: carves blocks out of its pool, recycles freed ones
               │  (rarely)
Kernel  :  brk() / mmap()  "give me more memory"                    ← a handful of calls
```

glibc uses two system calls to get memory from the kernel. `brk` moves the end of the main heap to grow it.[^brk] `mmap` creates a separate region.[^mmap] Allocations of 128 KiB or more get their own `mmap` region by default (`M_MMAP_THRESHOLD`). Smaller ones are carved out of the heap.[^mallopt]

### Example: one `malloc(8)`, four different sizes

| Layer | Amount | Why |
|---|---|---|
| What the program requests | 8 bytes | |
| What the allocator uses | 32 bytes | On 64-bit glibc, a chunk is at least 32 bytes. It includes a header that records its size, so `free` can find it, and it is 16-byte aligned.[^malloc-internals] |
| What glibc asks the kernel for | about 132 KiB, **once** | On the first call, the heap is empty. glibc calls `brk` for the request plus a 128 KiB margin (`M_TOP_PAD`).[^mallopt] |
| What actually occupies RAM | 4 KiB | Only the page that gets touched is backed by physical memory. |

The thousands of `malloc(8)` calls that follow are served from that pool **with no system call at all**. The kernel only hears from glibc again once the pool runs out.

## Freed memory usually stays with the allocator

When a program calls `free`, glibc generally keeps the block for reuse instead of returning it to the kernel. This is a deliberate trade-off, made for three reasons.

**Returning memory and requesting it again is expensive.** Programs repeatedly free and reallocate blocks of similar sizes, for example one set of buffers per request. If every `free` returned memory to the kernel, each cycle would cost a system call to give the memory back, another to get it again, a page fault on first access, and the kernel zeroing each page before handing it out again, so that one process never sees another's data.[^mmap] Reusing a block costs a few instructions.

**The kernel only takes back whole pages.** A 4 KiB page holds over a hundred small blocks. If even one of them is still in use, the page can't be returned.

**The heap can only shrink from the top.** The main heap is one contiguous region, and `brk` only moves its end:

```
start of heap                                       end (brk)
[ free  | free  | free  | free  | free  | LIVE ]
                                          ↑
           one live block at the top → nothing can be returned
```

Free memory trapped below a block that is still in use is called **fragmentation**. glibc returns the top of the heap to the kernel only when more than 128 KiB is free there (`M_TRIM_THRESHOLD`).[^mallopt] A program can call `malloc_trim(3)` to release free pages in the middle of the heap.[^malloc-trim]

Other allocators make different trade-offs. jemalloc, for instance, gradually returns memory that hasn't been reused for about 10 seconds by default (`opt.dirty_decay_ms`).[^jemalloc]

## Why the kernel's view can't find leaks

These two facts have a direct consequence: **neither the kernel nor the process's resident memory (RSS) can tell you whether a program leaks, or where.**

- Most `malloc` and `free` calls never reach the kernel, so the kernel doesn't see individual blocks.
- One page can hold both leaked and live blocks, so page-level data can't separate them.
- RSS mixes memory the program uses with memory the allocator keeps on purpose. A high RSS that never drops can be allocator policy, not a leak.

RSS is still a cheap and useful **warning signal**: memory that keeps growing is worth a closer look. But confirming a leak, and finding the responsible code, requires watching `malloc` and `free` themselves. dmld does this with uprobes (see [Attaching to a running process](../README.md#attaching-to-a-running-process)), and only once RSS has kept growing (see [Two-level monitoring](../README.md#two-level-monitoring)).

## Call stacks: who asked for the memory?

Knowing that a block was leaked isn't enough. A program calls `malloc` from thousands of places, and the useful question is *which code path* allocates memory that is never freed.

When a function calls another, the CPU saves a **return address**, the place to resume once the call finishes. These addresses stack up, one per active function. At the moment `malloc` is called, they describe the full path that led there:

```
malloc             ← the intercepted call
buffer_new         (buffer.c:31)
parse_request      (http.c:212)
handle_conn        (server.c:97)
main
```

This is the **call stack**. dmld captures it on every recorded allocation with `bpf_get_stackid`.[^bpf-helpers] The kernel stores the raw addresses and returns a `stack_id`. The same path always gets the same id, so dmld can add up live bytes per path and point at `parse_request` instead of at `malloc`. In user space, the addresses are then translated into function names, files and lines.[^blazesym]

To walk the stack, the kernel follows **frame pointers**: each function's frame stores a pointer to the previous one. Many binaries are built without them, because GCC stopped emitting them by default in 2004. In that case the walk stops early, typically at the libc, and the application's own functions are missing.[^frame-pointers] This is why dmld recommends building targets with `-fno-omit-frame-pointer` (C/C++) or `-C force-frame-pointers=yes` (Rust).

## Further reading

- glibc wiki, *MallocInternals*: how glibc's allocator is organized. <https://sourceware.org/glibc/wiki/MallocInternals>
- B. Gregg, *The Return of the Frame Pointers*. <https://www.brendangregg.com/blog/2024-03-17/the-return-of-the-frame-pointers.html>

## References

[^perf-event]: `perf_event_open(2)` man page: `PERF_COUNT_SW_PAGE_FAULTS_MIN` ("did not require disk I/O") and `PERF_COUNT_SW_PAGE_FAULTS_MAJ` ("required disk I/O"). <https://man7.org/linux/man-pages/man2/perf_event_open.2.html>
[^brk]: `brk(2)` man page. <https://man7.org/linux/man-pages/man2/brk.2.html>
[^mmap]: `mmap(2)` man page: anonymous mappings are initialized to zero. <https://man7.org/linux/man-pages/man2/mmap.2.html>
[^mallopt]: `mallopt(3)` man page: `M_MMAP_THRESHOLD`, `M_TOP_PAD`, `M_TRIM_THRESHOLD` (128 KiB each by default). <https://man7.org/linux/man-pages/man3/mallopt.3.html>
[^malloc-internals]: glibc wiki, *MallocInternals*. <https://sourceware.org/glibc/wiki/MallocInternals>
[^malloc-trim]: `malloc_trim(3)` man page. <https://man7.org/linux/man-pages/man3/malloc_trim.3.html>
[^jemalloc]: jemalloc manual: `opt.dirty_decay_ms` (default 10 s). <https://jemalloc.net/jemalloc.3.html>
[^bpf-helpers]: `bpf-helpers(7)` man page: `bpf_get_stackid`, `BPF_F_USER_STACK`. <https://man7.org/linux/man-pages/man7/bpf-helpers.7.html>
[^blazesym]: `blazesym`: address symbolization library. <https://github.com/libbpf/blazesym>
[^frame-pointers]: B. Gregg, *The Return of the Frame Pointers* (2024). <https://www.brendangregg.com/blog/2024-03-17/the-return-of-the-frame-pointers.html>
