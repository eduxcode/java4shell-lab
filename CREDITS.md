# Credits and provenance

## Original discovery and research

- **Quang Luong**: discovery, write-up and exploitation chains.
- **Calif.io**: disclosure of CVE-2026-114938 ("Java4Shell"), technical advisory
  and reference PoC.
- **Jenish Rakholiya**: exploit improvements.
- **Oracle**: CNA for the CVE and author of the fix (respins of 2026-11-17).

The primitive used in this lab, the `bzhiq`/`evmovdqub` underflow in the tail
handling of the Base64 intrinsic, is derived from that published work and is
reproduced here with attribution.

## Original work in this repository

**eduxcode**: https://github.com/eduxcode

### 1. Empirical correction of the trigger

The advisory mentions `64x'A' + '='` and `128x'A' + '='`. Measuring HotSpot's
`generate_base64_decodeBlock` stub shows that those inputs **do not reach the
vectorized code**: the gate is `length > 128`, and below it the scalar loop
handles the tail in Java.

This repository derives and validates the input that does trigger the bug:

- **129 bytes** (`128x'A' + '='`);
- general condition: `length > 128` and `length % 64 ∈ {1, 2, 3}`;
- store window: `dp = 48 * (length / 64)`, 64 bytes;
- buffer allocated by the JDK: `3 * ceil(length / 4) - paddings`;
- result: 62 bytes past the 98-byte buffer (`dp = 96`, store up to 159).

It also documents that **128 bytes** (127 `A` + `=`) is a **valid** input that
decodes 95 bytes without throwing, which explains the false negatives.

### 2. Instrumentation

- `poc/Oracle.java`: oracle that derives the length and the window, measures the
  first and last byte, and validates the count, instead of reporting "something
  changed".
- `poc/MaskUnderflow.java`: mask arithmetic emulated in pure Java, showing the
  root cause on CPUs without AVX-512.
- `target/DecodeServer.java`: target with per-endpoint counters, a realistic path
  (`/decode`), a safe path (`/decode-safe`) and a deterministic path
  (`/decode-exact`, with a victim object allocated after the buffer).
- `demo/`: Intel SDE setup, two-pane workflow, automatic `hs_err` capture and
  walkthrough.
- `deploy/`: optional package for a native AVX-512 instance, with Terraform.

### 3. Cloud-free execution path

The original development host (an Intel i5-8500) has no AVX-512, and QEMU TCG does
not emulate the required instructions. The repository uses the free
**Intel SDE 10.13.1** to emulate VBMI and rewrite CPUID, so the JVM reports
`UseAVX = 3` and executes the real stub. This makes the reproduction possible on
ordinary consumer hardware.

## Why attribution stays

Claiming the primitive as original work would be plagiarism and would not survive
technical review. The defensible contribution is the verification method, the
corrected trigger length and the instrumentation, and that is what is credited
above.
