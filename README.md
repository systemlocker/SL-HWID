# SL-HWID

A fault-tolerant, cross-platform hardware fingerprint. SL-HWID combines
over 14 independent signals, applying weighted shares to less stable values.
Drifted slots are quietly re-absorbed after each successful use. The point
is to prevent over-fitting to any single machine detail while avoiding
over-dependence on the exact hardware configuration: routine changes such as
swapping a monitor should not require a HWID reset.

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

SLHwidSession session;
try
{
    // SLHwid is both the namespace and the class, so qualify the call.
    session = SLHwid.SLHwid.Prepare(new SLHwidOptions());
}
catch (SLHwidDriftException error)
{
    Console.Error.WriteLine(error.Message);   // e.g. hardware drift past the threshold
    return;
}
Console.WriteLine(session.Hwid);
// ... after your server authorized this machine ...
session.Commit();   // re-center tolerance on current hardware
```

## Storage

This code relies on certain storage locations on the host machine.

Windows: the registry (`HKLM\SOFTWARE\SystemLocker`, falling back to HKCU
when the HKLM write is denied). If an elevated run enrolled the device in
HKLM, a later non-elevated run cannot update it; its `Commit` then keeps a
per-user copy of the same enrollment in HKCU, with the same key and HWID, and
later runs for that user use and refresh that copy. macOS:
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
- The percentage policy is 80% below eight enrolled slots and 70% from eight
  upward. New enrollment and re-centering require at least eight available
  slots, so current helpers begin on the 70% branch instead of accepting a
  weaker latch. Existing helpers can still recover below that floor; their
  migration waits until enough current slots exist.
- Platform identifiers, display identifiers, and software-environment signals
  are grouped so each correlated set consumes only one recovery slot.
- Existing schema-v1 and schema-v2 helpers remain recoverable. After
  successful authorization, `Commit` rewrites the helper with the current
  schema (v3) while preserving the HWID.
- Removable disks (USB, SD/MMC, mounted disk images) do not count toward the
  disk slot, and each monitor contributes a fixed-size digest, so a long
  monitor history no longer drops out of the display slot.
- `ForceReenroll` / `forceReenroll` also replaces a damaged store secret.
  Without it, a damaged secret is reported as corrupt data and left in place.
- `ExtraMandatory` / `extraMandatory` also applies to an existing helper.
  An enrolled factor must still match before it can become mandatory. A
  newly available factor is bound when `Commit` succeeds after authorization.
  Added locks preserve the HWID and apply to every application sharing the
  store; omitting them in a later call does not remove them.
- The persisted formats, helper name, and lock marker are identical across
  the C++ and C# implementations and across platforms.

Maintainers: see [Factor schema and migrations](FACTOR-SCHEMA.md) before
adding, removing, renaming, regrouping, or changing a collected signal.

## Security

> [!WARNING]
> Watch this repository (Watch → Custom → Releases) and update your
> dependency when a release ships: releases regularly add security
> enhancements.


## HOTFIX 2.0.1

Here's what we changed:

- The helper and its `SLStore` secret are always selected and written in the same hive, so an elevation change cannot pair values from different enrollments. If both hives contain complete enrollments, HKLM wins; use `ForceReenroll` to replace an intentionally abandoned generation.

- Windows collection does not require WMIC. The SMBIOS UUID and stable disk and volume properties come from native Windows APIs; PowerShell/CIM contributes optional signals, including NIC identity, under a bounded deadline and never replaces a native value.

- Factor normalization drops implausible values before enrollment, including byte-count mistakes for RAM, nil/example UUIDs, all-zero/all-`f` identifiers, malformed MACs, oversized values, and common firmware placeholders.
