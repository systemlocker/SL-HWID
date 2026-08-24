# SL-HWID

A fault-tolerant, cross-platform hardware fingerprint. SL-HWID combines
**14 hardware factors** by default — any two can fail or change without
changing the identifier, and drifted factors are quietly re-absorbed after
each successful use. The point is to prevent over-fitting to any single
machine detail while avoiding over-dependence on the exact hardware
configuration: no more support tickets because a user swapped a monitor,
no more free re-activations because a pirate spoofed one value.

Under the hood, a random high-entropy key is shared across the factors with
a threshold scheme; the identifier is a domain-separated hash of that key.
One factor — SL-HWID's own persisted random value — is **hard-locked**:
changing or deleting it always requires re-activation, since that is
tampering rather than drift.

This repository contains two independent, self-contained implementations
that share the same on-disk state format:

- [`cpp/`](cpp/) — C++20 library, zero dependencies (embedded SHA-256,
  platform CSPRNG). Windows, macOS, Linux.
- [`csharp/`](csharp/) — .NET 8 library, zero NuGet dependencies.
  Windows, macOS, Linux.

Both are released under the [Elastic License v2 license](LICENSE).

## C++ quickstart

```cmake
add_subdirectory(sl-hwid/cpp)
target_link_libraries(your_app PRIVATE slhwid)
```

```cpp
#include <slhwid/slhwid.hpp>

auto session = slhwid::prepare({});
if (!session)
    return report(session.error().message);   // e.g. hardware drift past the threshold
std::cout << session->hwid() << "\n";
// ... after your server authorized this machine ...
session->commit();   // re-center tolerance on current hardware
```

Build the C++ library with CMake ≥ 3.20:

```sh
cmake -S cpp -B cpp/build && cmake --build cpp/build --config Release
```

## C# quickstart

Add `csharp/SLHwid/SLHwid.csproj` as a project reference, then prepare the
shared device identifier:

```csharp
using SLHwid;

var session = SLHwid.Prepare(new SLHwidOptions());
Console.WriteLine(session.Hwid);
// ... after your server authorized this machine ...
session.Commit();   // re-center tolerance on current hardware
```

## Storage

This code relies on certain storage locations on the host machine.

Windows: the registry (`HKLM\SOFTWARE\SystemLocker`, falling back to HKCU
when the HKLM write is denied). macOS:
`~/Library/Application Support/SystemLocker`. Linux:
`$XDG_DATA_HOME/systemlocker` (else `~/.local/share/systemlocker`). Pass
`storePath` / `StorePath` to redirect storage to a directory.

All applications using the same default store (or the same explicit store
directory) share one `device` helper and therefore report the same HWID for
the current user and device.

The HWID determination is deliberately best-effort, but it is expected to
match runs of the same application, and, in most cases, across any
application run on the same device and operating system.

Prepare and Commit serialize changes with a short-lived `.slhwid.lock`
marker. Locks held by a live process wait for up to 30 seconds; markers left
by a terminated process are recovered automatically. Re-enrolling or
changing mandatory slots affects every application that shares the store.

## Semantics

- The first `Prepare` on a machine enrolls it (a new random key); later
  calls recover the same key as long as the threshold holds. Commit after
  each successful authorization to absorb drifted factors.
- Fewer factors than 14 may be available on a given machine; the threshold
  adapts (80% agreement above ten factors, 70% for five to ten). Fewer
  than five available factors throws an error, instead of accepting a
  weaker latch.
- The persisted formats, helper name, and lock marker are identical across
  the C++ and C# implementations and across platforms.
