# java4shell-lab

A self-contained, local lab for **CVE-2026-114938 ("Java4Shell")**: a heap
corruption in the OpenJDK HotSpot AVX-512 Base64 intrinsic.

Use it to **check whether your JDK is affected**, to **validate a mitigation or
patch**, or to **study the root cause** with a reproducible, instrumented target.

Everything runs locally. The target listens only on `127.0.0.1:8080`, and no cloud
account or AVX-512 hardware is required: the lab uses the free
[Intel SDE](https://www.intel.com/content/www/us/en/developer/articles/tool/software-development-emulator.html)
to emulate AVX-512 VBMI.

> **Educational and defensive use only.** Run this lab only on systems you own or
> are explicitly authorized to test. It demonstrates heap corruption and a
> resulting denial of service. It does **not** implement remote code execution.

---

## Table of contents

1. [Credits](#credits)
2. [Quick start](#quick-start)
3. [Is my Java vulnerable?](#is-my-java-vulnerable)
4. [Vulnerability summary](#vulnerability-summary)
5. [Trigger analysis](#trigger-analysis)
6. [Running the lab](#running-the-lab)
7. [Example output](#example-output)
8. [Mitigation and remediation](#mitigation-and-remediation)
9. [Detection](#detection)
10. [Scope and limitations](#scope-and-limitations)
11. [Repository layout](#repository-layout)
12. [License](#license)

---

## Credits

- **Lab, instrumented target, oracle and verification method:** [eduxcode](https://github.com/eduxcode)
- **Original trigger primitive:** Quang Luong / [Calif.io](https://calif.io) (public advisory for CVE-2026-114938)

See [CREDITS.md](CREDITS.md) for a detailed breakdown of what comes from the
original research and what this repository contributes.

## Quick start

Requirements: Linux x86-64, `curl`, `tar`, `docker`, `python3`; `tmux` for the
two-pane demo.

```bash
git clone https://github.com/eduxcode/java4shell-lab
cd java4shell-lab

./demo/setup-sde.sh   # one time: downloads Intel SDE, extracts JDK 17.0.21, builds
./run-lab.sh          # non-interactive, end-to-end check
```

`run-lab.sh` exits `0` when it reproduces the corruption on the vulnerable runtime
and confirms that `-XX:-UseBASE64Intrinsics` mitigates it.

## Is my Java vulnerable?

A JVM is exposed only when **all** of the following are true.

**1. The version is in the affected range.**

```bash
java -version
```

| Status | Versions |
|---|---|
| Affected (per Oracle) | `8u511b33-perf`, `17.0.21.0.3`, `21.0.13.0.3`, `25.0.5.0.3`, `27.0.1.0.3` |
| Fixed | `17.0.21.1`, `21.0.13.1`, `25.0.5.1`, `27.0.1.1`, `8u513` |

**2. The CPU exposes the required instructions.** The vulnerable stub is selected
only on x86-64 with `avx512f`, `avx512bw`, `avx512vbmi` and `bmi2`.

```bash
grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -E '^(avx512f|avx512bw|avx512vbmi|bmi2)$'
```

**3. The JVM actually uses the intrinsic.**

```bash
java -XX:+PrintFlagsFinal -version | grep -E 'UseAVX|UseBASE64Intrinsics'
```

`UseAVX = 3` together with `UseBASE64Intrinsics = true` means the vectorized
decoder is active. On CPUs without AVX-512 VBMI, `UseAVX` resolves to `2` and the
vulnerable code path is never taken.

**4. Your application decodes attacker-controlled Base64.** Any
`java.util.Base64` decode path reachable from untrusted input qualifies (HTTP
bodies, headers, tokens, uploads). Spring Security is not required.

### Test your own JDK empirically

Build the oracle with the JDK you want to test and run it on an AVX-512 VBMI
host (or under the SDE that `setup-sde.sh` installs):

```bash
javac -d /tmp/j4s poc/Oracle.java

# native AVX-512 VBMI host
java -Xbatch -XX:-TieredCompilation -XX:CompileThreshold=500 -XX:UseAVX=3 \
     -cp /tmp/j4s Oracle --warmup 5000

# any other x86-64 host, using the SDE installed by setup-sde.sh
J4S_SDE=1 demo/.tools/sde/sde64 -icx -- \
  java -Xbatch -XX:-TieredCompilation -XX:CompileThreshold=500 -XX:UseAVX=3 \
       -cp /tmp/j4s Oracle --warmup 5000
```

| Exit code | Meaning |
|---|---|
| `0` | Corruption reproduced: the runtime is **vulnerable** |
| `3` | Not reproduced: patched, mitigated, or intrinsic not in use |
| `2` | Usage or runtime error |

To test a container image instead, set `JAVA_IMG` (and optionally
`PATCHED_IMAGE`) when running `deploy/run-on-instance.sh` on an AVX-512 host. See
[deploy/README.md](deploy/README.md).

The oracle writes inside a scratch array, so it measures the out-of-bounds window
without crashing the JVM. Run **one trigger per JVM process**: the first
`IllegalArgumentException` deoptimizes `decode0`, and later calls fall back to the
scalar loop.

## Vulnerability summary

| Item | Value | Source |
|---|---|---|
| Published | 2026-11-17 21:32 UTC by Oracle (secalert) | MITRE CVE record |
| Weakness | CWE-122, component `hotspot/compiler` | NVD / Corretto changelog |
| CVSS 3.1 | **8.1** (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`) | NVD |
| CVSS 4.0 | **9.2** | Calif.io |
| SSVC (CISA) | `exploitation: none`, `automatable: no` | NVD (ADP) |
| Hardware gate | x86-64 with `avx512f`, `avx512bw`, `avx512vbmi`, `bmi2` | Calif.io |

## Trigger analysis

The public advisory mentions `64x'A' + '='` and `128x'A' + '='`. Measuring the real
stub shows that **those inputs never reach the vectorized code**.

`generate_base64_decodeBlock` enters the AVX-512 path only when
`length > 128` (`cmpl(length, 128); jle L_bruteForce`). Below that, a scalar loop
decodes blocks of four and the tail is handled in Java, with no out-of-bounds
write.

The input that actually triggers the bug is **129 bytes** (`128x'A' + '='`):

```
length = 129      -> AVX-512 path
64-byte loop      : 129 -> 65 -> 1        (dp = 48 + 48 = 96)
tail              : 1 byte ('=')
output_size       : (1 / 4) * 3 - 1 = -1
bzhiq(mask, -1)   -> 0xffffffffffffffff   (BZHI with index >= 64 clears nothing)
evmovdqub         -> 64-byte store at dp = 96
allocated buffer  : 3 * ceil(129 / 4) - 1 = 98
result            : bytes 96..159 written, 62 bytes past the end of the array
```

General condition: `length > 128` **and** `length % 64 ∈ {1, 2, 3}`, so that a tail
of one to three bytes remains with a trailing `=`.

A **128-byte** input (127 `A` + `=`) is valid: it decodes 95 bytes and throws
nothing. This explains why naive attempts at the advisory's lengths report
"not vulnerable".

## Running the lab

### One command (two tmux panes)

```bash
./demo/run-demo.sh
```

### Two terminals

```bash
# Terminal 1: target
./demo/target.sh

# Terminal 2: attacker (after the target reports it is up)
./demo/attacker.sh
```

Under emulation the JVM takes roughly 25-30 seconds to start answering.

### What each component shows

| Component | Purpose |
|---|---|
| `poc/MaskUnderflow.java` | Root cause in pure Java: the mask arithmetic underflow, on any CPU |
| `poc/Oracle.java` | Derives the trigger length and the exact write window; validates first/last byte and count |
| `poc/Base64Trigger.java` | Bounded 129-byte PoC, one process per length |
| `target/DecodeServer.java` | HTTP target with per-endpoint counters and a victim object allocated after the buffer |

Target endpoints:

| Endpoint | Behavior |
|---|---|
| `POST /decode` | Realistic path: `Base64.getDecoder().decode(String)` |
| `POST /decode-exact` | Deterministic path: a victim object is allocated right after the buffer |
| `POST /decode-safe` | Same decoding into a 4096-byte buffer (no corruption) |
| `GET /health` | Runtime version and counters |

Details of the two-pane walkthrough are in [demo/README.md](demo/README.md).

### Hardware paths

| Path | Result |
|---|---|
| Native, CPU without AVX-512 | Not reproducible: the JVM never selects the intrinsic (`UseAVX=2`) |
| QEMU TCG | Not viable: TCG rejects `avx512vbmi`; `vpermb` raises SIGILL |
| **Intel SDE 10.13.1** | **Works**: emulates VBMI and rewrites CPUID so the JVM reports `UseAVX=3` |
| Native AVX-512 VBMI (Ice Lake+, Zen 4+) | Works without emulation; see [deploy/README.md](deploy/README.md) |

Verify the emulation:

```
$ sde64 -icx -- jdk/bin/java -XX:+PrintFlagsFinal -version | grep UseAVX
     intx UseAVX = 3 {ARCH product} {default}
```

## Example output

Observed on a host without AVX-512, using the SDE:

```
oracle .......................... [HIT] 128x'A'+'=' len=129 buffer=98
                                  tail=[96,159] OOB=62
POST /decode-exact .............. http=400
                                  {"buffer":98,"victim_len":-1700370022,"victim0":105}
target .......................... SIGSEGV in G1RegionMarkStatsCache::add_live_words
                                  hs_err_pid captured
```

The negative `victim_len` shows that the header of the object allocated right
after the buffer was overwritten by the 62 out-of-bounds bytes. The next GC cycle
finds an inconsistent heap and the JVM aborts, as a natural GC would.

## Mitigation and remediation

1. **Immediate:** start the JVM with `-XX:-UseBASE64Intrinsics`. Decoding stays
   correct and only becomes slower. Validate under realistic load.
2. **Permanent:** upgrade to `17.0.21.1`, `21.0.13.1`, `25.0.5.1`, `27.0.1.1` or
   `8u513`.
3. **Post-patch verification:** re-run the oracle on an AVX-512 host (or under the
   SDE) and expect exit code `3` / `NOT REPRODUCED`.
4. **Do not rely on** input size limits, rate limiting or a WAF. The payload uses
   only valid Base64 characters and ends with `=`, so it is indistinguishable from
   ordinary malformed traffic.

## Detection

- Base64 request bodies or headers of **129 bytes** (more generally `length > 128`
  and `length % 64 ∈ {1, 2, 3}`) ending in `=`.
- Spikes of `400 invalid base64` followed by JVM restarts or `hs_err_pid*.log`
  files.
- `IllegalArgumentException` from `java.util.Base64` in application logs.
- Services that decode Base64 on a non-fixed runtime should be prioritized
  regardless of the SSVC `exploitation: none` rating.

## Scope and limitations

- The lab reproduces **heap corruption and denial of service**. It does not
  provide remote code execution.
- The out-of-bounds write has **fixed content**: it is the decoded output, which for
  the trigger is `0x69 0xa6 0x9a` repeated. The attacker does not control the
  spilled bytes.
- Public material does not include a heap-grooming primitive or a complete
  writer/reader chain toward the code cache. Per the advisory, exploitation chains
  are not public and there is no universal exploit.
- Base image note: `openjdk:17.0.6` does not exist on Docker Hub. The lab uses
  `eclipse-temurin:17.0.6_10-jdk` for container builds and
  `eclipse-temurin:17.0.21_9-jdk` for the SDE runtime.
- `-XX:UseAVX=2` also avoids the vulnerable path, but the precise switch for this
  issue is `-XX:-UseBASE64Intrinsics`.
- A patched Temurin tag was not yet published on Docker Hub as of 2026-11-18;
  see [deploy/README.md](deploy/README.md) for remediation testing options.

## Repository layout

```
target/DecodeServer.java   Instrumented target (/decode, /decode-exact, /decode-safe, /health)
target/Dockerfile          eclipse-temurin base image (BASE_IMAGE build arg for patched runtimes)
poc/Oracle.java            Oracle: derives the trigger and the out-of-bounds window
poc/MaskUnderflow.java     Root cause in pure Java (runs on any CPU)
poc/Base64Trigger.java     Bounded 129-byte PoC (one process per length)
demo/                      SDE setup and two-pane walkthrough
deploy/                    Optional package for a native AVX-512 instance
run-lab.sh                 Non-interactive end-to-end test
CREDITS.md                 Attribution of the original research and this lab
```

## License

Code is released under the **MIT** license (see [LICENSE](LICENSE)). The trigger
primitive belongs to the original researchers and is credited in
[CREDITS.md](CREDITS.md).

This material is intended for education and defense. Use it only on systems you
own or have written authorization to test, and do not present it as a weaponized
exploit.
