# CVE → First Fixed Ubuntu GCP Image

## Purpose

A CLI tool that, given a CVE identifier, returns the name of the **earliest published Ubuntu 24.04 (Noble) GCP image whose package manifest contains a fix** for that CVE.

## Usage

```
cve-first-fixed-image CVE-YYYY-NNNN
```

On success: prints the image name (manifest basename without extension) to stdout and exits 0.

```
$ cve-first-fixed-image CVE-2024-6387
ubuntu-noble-amd64-server-20240703
```

On failure: prints a diagnostic to stderr and exits non-zero.

| Exit code | Meaning                                                          |
| --------- | ---------------------------------------------------------------- |
| 0         | First-fixed image found, printed on stdout                       |
| 1         | CVE not found in the Noble OVAL feed                             |
| 2         | CVE is known but no released Noble image yet contains the fix    |
| 3         | CVE affects no package present in the Noble image manifests      |
| 4         | Network / data-source error (GCS, security-metadata, parse)      |
| 64        | Bad arguments (malformed CVE id, etc.)                           |

## Inputs

- **CVE identifier** — argument 1, format `CVE-\d{4}-\d{4,}` (case-insensitive, normalized to upper-case).

## Data Sources

1. **Ubuntu 24.04 OVAL feed** (CVE → fixed package versions)
   `https://security-metadata.canonical.com/oval/com.ubuntu.noble.cve.oval.xml.bz2`

   Used to determine, for the given CVE:
   - Which binary/source packages are affected
   - The fixed version of each affected package (the version at which the CVE is resolved in Noble)
   - Whether the CVE applies to Noble at all (vs. needs-triage / does-not-exist / DNE-in-Noble)

2. **Ubuntu Noble GCP image manifests** (image → installed package versions)
   `gs://ubuntu_os_cloud/ubuntu-noble-amd64-server-YYYYMMDD.manifest`

   Each manifest is a plain-text file with one `<package>\t<version>` line per installed package. Some packages appear with a `:arch` suffix (e.g. `libc6:amd64`); the tool strips this and uses the bare package name to match OVAL.

   The image **name** corresponding to a manifest is the manifest filename without the `.manifest` extension (e.g. `ubuntu-noble-amd64-server-20240703`).

   At time of writing the bucket contains 374 manifests dating back to **2023-11-04** (pre-GA daily builds); not every calendar day has a manifest.

   > Note: the spec given uses `YYYMMDD` in the filename; the actual published convention is `YYYYMMDD` (8 digits). The tool assumes 8-digit dates.

## Algorithm

1. **Fetch and parse OVAL.**
   - Download `com.ubuntu.noble.cve.oval.xml.bz2`, decompress in memory, parse XML.
   - Locate the definition matching the input CVE id.
   - Extract the set of `(source_package, fixed_version)` pairs that resolve the CVE in Noble.
   - If the CVE is not present, exit 1.
   - If the CVE is present but has no fixed version recorded for Noble (e.g. `<unfixed>` / open), exit 2.

2. **Enumerate manifests, newest → oldest.**
   - List the bucket once via `gcloud storage ls gs://ubuntu_os_cloud/ubuntu-noble-amd64-server-*.manifest`, extract the `YYYYMMDD` from each object name, and sort descending. This list is the iteration order; we walk backwards in time over the days that actually have manifests.
   - The listing is cached on disk (TTL ~1 hour) so subsequent CLI runs avoid the round-trip.
   - Probing every calendar day was considered and rejected: most days have no manifest, and 700+ wasted probes against an authenticated API is both slow and unfriendly.

3. **Walk backwards, narrowing the boundary.**
   - For each manifest in the descending list, download and parse it into a `{package: version}` map.
   - Decide `contains_fix(manifest)`:
     - For each `(pkg, fixed_version)` from OVAL, look up `pkg` in the manifest.
       - If `pkg` is not present in *any* manifest examined so far, it is not part of these images — exit 3 once exhausted.
       - If present and `manifest[pkg] >= fixed_version` (dpkg version comparison), this package is fixed.
     - The manifest "contains the fix" iff **every** affected package's installed version is `>= fixed_version`.
       (Conservative: a partial fix is treated as unfixed so the answer is the first image where the CVE is fully addressed.)
   - Track `youngest_unfixed = None` and `oldest_fixed_so_far = None`.
     - While `contains_fix` is true, update `oldest_fixed_so_far = current_manifest` and continue to the next-older manifest.
     - As soon as `contains_fix` is false, stop. `oldest_fixed_so_far` is the answer.
   - If we exhaust the list without ever seeing an unfixed manifest, the oldest manifest itself was already fixed — return it (and emit a warning to stderr that the boundary predates the available manifests).
   - If the **newest** manifest is unfixed, no released image contains the fix yet — exit 2.

4. **Output.**
   - Print `oldest_fixed_so_far`'s image name (filename minus `.manifest`) to stdout.

## Version Comparison

Package versions in Ubuntu manifests follow Debian version semantics (`epoch:upstream-debian_revision`). The tool MUST use a proper dpkg-compatible comparator:

- Prefer `python-debian`'s `debian.debian_support.Version` if implemented in Python.
- Or shell out to `dpkg --compare-versions <a> ge <b>`.
- String comparison is **not acceptable**.

## Authentication & Access

- The `ubuntu_os_cloud` bucket is **not** anonymously readable — both `storage.objects.list` and `storage.objects.get` return `403 AccessDenied` without credentials. (The original spec assumed public access; it was wrong.)
- Therefore the tool requires the user to be authenticated to GCP with read access to the bucket. Setup:
  ```
  gcloud auth login
  ```
  (Canonical employees with bucket access are sufficient; the bucket appears to be readable by signed-in users by default.)
- Access strategy used by the tool:
  - **Listing** — `gcloud storage ls` (subprocess). Required, since the Python `urllib` path cannot easily authenticate without `google-cloud-storage`.
  - **Per-object fetch** — HTTPS GET against `https://storage.googleapis.com/<bucket>/<object>` with an `Authorization: Bearer <token>` header. The token is obtained once per run via `gcloud auth print-access-token` and memoized. This avoids paying gcloud's ~1 s Python startup on every manifest fetch.
  - **Fallback** — if HTTPS fetch fails for a non-404 reason, fall back to `gcloud storage cat`.
- The OVAL URL is unauthenticated HTTPS.

## Caching

The cache is what turns this from a 2-minute query into a 2-second one. Measured on a cold cache: a first run for CVE-2024-6387 was ~140 s (OVAL download + bucket listing + ~30 manifest fetches). A warm-cache re-run was 2.5 s.

- **OVAL XML** — TTL ~1 hour (`OVAL_TTL_SECONDS = 3600`). No ETag check; the feed is small enough that re-downloading hourly is fine.
- **Bucket listing** — TTL ~1 hour (`LISTING_TTL_SECONDS = 3600`). Stored as a plain text file of `YYYYMMDD` strings.
- **Individual manifest contents** — cached **indefinitely** keyed by object name. Manifests are immutable once published.

Cache location: `${XDG_CACHE_HOME:-$HOME/.cache}/cve-first-fixed-image/`.

The CLI accepts `--no-cache` to bypass all caches and `--refresh` to force OVAL re-download.

## Non-Goals

- Other Ubuntu releases (22.04, 20.04, …). The tool is Noble-only; multi-release support is a future extension.
- Other clouds or architectures. Noble amd64 server GCP images only.
- Resolving the GCP image *resource* name (e.g. `projects/ubuntu-os-cloud/global/images/...`). The output is the manifest-derived image basename; mapping that to a `gcloud compute images` resource is out of scope.
- Backports / ESM. The tool uses only the standard Noble OVAL feed.

## OVAL → binary package mapping

OVAL's definitions use two different shapes depending on whether the CVE affects userspace packages or the kernel.

### Userspace CVEs (e.g. CVE-2024-6387)

`dpkginfo_object` does not store the binary package name directly. The lookup is:

```
definition (CVE-2024-6387)
  └── criterion test_ref="…tst:202463870000000"
        └── dpkginfo_test
              ├── object_ref ──► dpkginfo_object
              │                    └── name var_ref="…var:202463870000000"
              │                          └── constant_variable
              │                                ├── value: openssh-client
              │                                ├── value: openssh-server
              │                                ├── value: openssh-sftp-server
              │                                ├── value: openssh-tests
              │                                ├── value: ssh
              │                                └── value: ssh-askpass-gnome
              └── state_ref  ──► dpkginfo_state
                                   └── evr operation="less than": 1:9.6p1-3ubuntu13.3
```

So one criterion yields a `FixRequirement(binaries=[...], fixed_version="...")`. A definition may have multiple criterions (e.g. several source packages, or a `criteria operator="OR"` over alternatives); a manifest "contains the fix" iff every requirement is satisfied: for each requirement, every installed binary in the list is at `>= fixed_version`. Binaries not installed in the manifest don't block the fix (they simply aren't on the image).

### Kernel CVEs (e.g. CVE-2026-23268)

Kernel CVEs use a completely different structure. The criterions reference `uname_test` (runtime "is kernel X running?" checks) and `variable_test` (version comparison against the running kernel version) — **not** `dpkginfo_test`. The `variable_test` has no structured link back to a source-package name; the only place the flavour appears is the criterion's `comment` attribute:

```xml
<criterion test_ref="oval:com.ubuntu.noble:tst:2025402460000050"
           comment="linux-gcp-6.17 package in noble was vulnerable but has been fixed (note: '6.17.0-1009.9~24.04.3')." />
```

The parser matches that comment with the regex
`^(?P<pkg>\S+) package in noble was vulnerable but has been fixed \(note: '(?P<ver>[^']+)'\)` and produces a kernel `FixRequirement`. Criterions without "has been fixed" (i.e. unfixed flavours, runtime-only `uname_test`) are skipped.

#### Series-aware manifest matching

GCP image manifests don't contain the OVAL source name `linux-gcp-6.17` directly — they contain the meta-package `linux-gcp` at a version like `6.17.0-1013.13~24.04.1`. The matcher therefore:

1. **Direct match** — if the OVAL flavour name (e.g. `linux-gcp`) is itself a binary in the manifest, compare its installed version against the fix.
2. **Series fallback** — if the OVAL flavour ends in `-X.Y` (e.g. `linux-gcp-6.17`), split into `stem`+`series`. If the manifest has the stem at a version whose upstream part begins with `X.Y.`, treat that as the install of that HWE series.
3. **Not applicable** — if neither matches, the flavour isn't carried by this image; the requirement is silently satisfied (the vulnerable kernel simply isn't installed).

A manifest "contains the fix" iff every applicable requirement is satisfied. Inapplicable requirements (flavour not installed) never block.

### Caveats

- This is the conservative reading. Definitions with nested `AND`/`NOT` semantics (uncommon for Ubuntu CVE OVAL) are evaluated as if all leaves had to be fixed, which never produces a false-positive but could push the boundary later than strictly required.
- A CVE whose only "has been fixed" entries are for flavours not present in any GCP image manifest (e.g. CVE-2024-1086, fixed only for `linux-raspi-realtime`) yields exit 3 — the CVE simply doesn't affect this image lineage.
- The criterion-comment parsing is a soft dependency on Canonical's OVAL generator wording. If they reword the "was vulnerable but has been fixed" boilerplate, the kernel path silently degrades to "no fix recorded" — surface this with `--verbose` if a kernel-CVE result looks wrong.

## Open Questions / Assumptions

- **OVAL granularity:** assumed that the Noble OVAL feed records one fixed version per affected source package per CVE. If a CVE has multiple staged fixes (e.g. partial fix then full fix), the tool treats the OVAL-recorded version as authoritative.
- **Manifest completeness:** assumed every published Noble GCP image has a corresponding `*.manifest` object in the bucket and that the dates in filenames reflect publication order.
