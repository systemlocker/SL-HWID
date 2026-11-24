# Factor schema and migrations

SL-HWID separates **raw signals** from **recovery slots**. Platform collectors
gather raw signals on a best-effort basis. The schema projection then decides
which signals participate directly and which share a capped failure domain.
Only projected slots affect the recovery threshold.

## Current schema (v3)

Direct slots are `slstore`, `machine_guid`, `cpu_id`, `fixed_disk_serial`,
`ram_total`, `volume_id`, `firmware`, `tpm_ek`, `memory_modules`,
`nic_identity`, and `battery_serial`.

Grouped slots are:

| Recovery slot          | Raw signals                                                      | Reason                                                                                        |
| ---------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `platform_identity`    | `system_uuid`, `board_serial`, `system_serial`, `chassis_serial` | These often come from the same firmware tables and should not receive four independent votes. |
| `display_group`        | `gpu_id`, `edid_digests`                                         | GPUs, docks, and monitors are legitimate replacement or mobility events.                      |
| `software_environment` | `computer_name`, `os_build`                                      | Renames and operating-system updates are correlated software changes.                         |

`fixed_disk_serial` lists only non-removable disks, so plugging in a USB
drive or SD card does not count as drift:

- Windows: every physical disk except USB, SD, MMC, and mounted disk images
  (storage bus types 7, 12, 13, and 15), read from the storage descriptor or
  from `MSFT_PhysicalDisk`.
- macOS: the internal NVMe and SATA buses reported by `system_profiler`.
- Linux: block devices with a serial that are neither marked removable nor
  attached through USB.

`edid_digests` is derived from `monitor_edid` during normalization: one
SHA-256 digest per monitor, sorted. Windows keeps the EDID of every monitor
ever attached, so the full inventory regularly exceeded the 4096-byte factor
limit and silently dropped out of schema v2; the digests stay small.

### Earlier schemas

Schema v2 is identical except that its direct disk slot is `disk_serial` (all
physical disks, removable ones included) and its `display_group` hashes
`gpu_id` and the full `monitor_edid` inventory. Schema v1 is the original
ungrouped projection. Both remain readable: an existing helper recovers with
its own schema, and `Commit` rewrites it in v3 around the same key, so the
HWID does not change.

A group is present when at least one member is present. Its value is a
domain-separated SHA-256 digest over the group name and the complete,
fixed-order member list, including empty members. Any member change changes
the group, but the entire group can lose only one threshold vote.

## Multi-instance values

Signals with several instances (disks, memory modules, NICs, monitors, GPUs,
firmware strings) use one canonical form in every implementation: each member
is trimmed of ASCII whitespace, empty members are dropped, and the rest are
sorted bytewise and joined with `|`. Never sort with a culture-aware
comparer: the value would change with the user's language settings.

## Sanity filtering

Normalization rejects a raw value before projection when its UTF-8 encoding
exceeds 4096 bytes, it is a known firmware placeholder, or its slot-specific
shape is implausible. `ram_total` is decimal bytes and must be at least
134217728 (128 MiB - change if your application could live on older Linux
machines). UUID inputs accept 32 hexadecimal digits or the canonical
hyphenated form, excluding nil, all-`f`, and the common
`12345678-1234-1234-1234-123456789abc` example. `slstore` and `tpm_ek` are
64 hexadecimal digits; MAC/NIC instances are 12 hexadecimal digits.
Identifier and serial slots reject empty multi-instance members, known
placeholder components, and values made entirely of zeroes or `f`s. These
checks are deliberately conservative: they catch unit mistakes and sentinel
data without trying to guess vendor-specific serial-number formats.

`memory_modules` filters invalid serials individually and retains the usable
modules as one slot. Already valid inventories retain their existing order and
duplicates. The 4096-byte input limit still applies before filtering. A newly
usable inventory joins an existing enrollment only on a successful `Commit`;
the recovered HWID stays unchanged.

The percentage policy is `ceil(80% × slots)` below eight slots and
`ceil(70% × slots)` from eight upward. New enrollment and re-centering require
at least eight slots, so current helpers begin on the 70% branch. The threshold
is always greater than the number of mandatory slots. Legacy recovery uses the
threshold stored in its helper, so this stronger floor does not strand an
existing installation.

The minimum of eight is one below the conservative nine-slot physical-machine
floor: persisted SL-HWID secret, CPU, disk, RAM, volume, firmware, permanent
NIC, platform identity, and software environment. That floor assumes the
machine GUID, TPM, display group, memory-module serials, and battery serial are
all unavailable. The one-slot margin covers one additional collector failure;
this line can be drawn anywhere however.

## Changing factors safely

The authoritative projection tables are beside `ProjectFactors` in
`csharp/SLHwid/SLHwidCore.cs` and `projectFactors` in
`cpp/src/slhwid.cpp`. Keep both implementations byte-for-byte compatible.

To add a signal:

1. Collect it best-effort on each supported operating system. An unavailable
   signal must not prevent collection of the others.
2. Normalize it consistently in both implementations. Prefer stable,
   manufacturer-assigned identity over a current configuration value.
3. Decide whether it represents an independent failure domain. Add it as a
   direct slot only when it does; otherwise add it to an existing or new group.
4. Update both language implementations and add cross-language tests for the
   projected slot name and value.
5. Recheck threshold boundaries. Adding the eighth slot changes the percentage
   branch, so test the effective factor counts found on supported platforms.
6. Recalculate `MinimumFactors` / `kMinimumFactors`. If a factor or group is
   added, removed, or made less portable, the good-faith availability floor and
   its one-slot margin must change with it.

To remove, rename, regroup, or reinterpret a signal:

1. Do not alter an existing schema projection. Old helpers need exactly the
   slot names and values used when they were enrolled.
2. Add a new schema version and retain the old projector and parser for the
   promised migration window (v3 did this for v2: see "Earlier schemas").
3. Collect enough raw data to project both the old and new schemas.
4. Recover with the helper's stored schema. Only after the application accepts
   the authentication should `Commit` project the current schema and rewrite
   the helper around the same recovered key.
5. Map legacy mandatory names to their current direct or grouped slot. A hard
   lock must not silently disappear during migration.
6. Add tests proving old-helper recovery, no write before `Commit`, migration
   on `Commit`, unchanged HWID, and current-helper recovery afterward.

Schema v1 and v2 support is intentionally retained for several releases. Their
factor lists are therefore historical compatibility code, not lists to clean
up when the current schema changes.

## Collector guidance

TPM endorsement identity, permanent NIC identity, memory-module inventory,
system/chassis serials, and battery serial are optional. Firmware permissions,
virtual machines, older hardware, and operating-system tools can make any of
them unavailable. Collector failures should produce an absent signal, never a
synthetic placeholder or an application failure.

Windows essentials use native operating-system APIs. `system_uuid` is the
SMBIOS Type-1 UUID read through `GetSystemFirmwareTable`; it is not Windows'
derived `ComputerHardwareId`. Do not introduce a WMIC dependency: the utility
is absent on current Windows installations. CIM-based signals are optional,
bounded enrichment and never overwrite a value obtained natively. Permanent
NIC addresses come from CIM: `Win32_NetworkAdapter` first (it is normally
empty), then `MSFT_NetAdapter` adapters that have a physical connector and
are not virtual.

On Windows, TPM identity first uses the Platform Crypto Provider's `PCP_EKPUB`
property. Its RSA public blob is encoded as ASN.1 `RSAPublicKey` and hashed with
SHA-256, matching `Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256`. PowerShell
remains the fallback if native reading or encoding fails. Existing TPM shares
therefore recover through either source without changing their value or the
helper format. When native access becomes available, collection switches to it
automatically; a previously unavailable TPM can be added on `Commit` after
successful authentication. Native queries are silent and never request elevation.

Treat collected values as device identifiers: do not log them, send them to a
server, or expose them in error messages. The helper stores threshold shares,
not the raw values.
