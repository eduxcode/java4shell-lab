# Deploying on an AVX-512 instance

This is optional. The default lab (`./run-lab.sh`) already works on any x86-64
Linux host through Intel SDE. Use this package when you want to run the vulnerable
code on **native** AVX-512 VBMI hardware, or to test a container image.

Hosts without `avx512vbmi` (for example an Intel i5-8500) do not execute the
vulnerable code, and QEMU does not help: TCG refuses the features.

```
qemu-x86_64: warning: TCG doesn't support requested feature: ...ECX.avx512vbmi [bit 1]
vpermb=SIGILL
```

KVM only helps if the **host** has AVX-512, so a native reproduction needs
Ice Lake+ / Zen 4+ hardware.

---

## Option 1: an instance you already have

```bash
# 1) repackage (whenever you change the sources)
./deploy/package.sh

# 2) copy (replace <IP> and the key path)
scp -i ~/.ssh/<YOUR_KEY>.pem deploy/java4shell-lab.tgz ec2-user@<IP>:/tmp/

# 3) run the lab
ssh -i ~/.ssh/<YOUR_KEY>.pem ec2-user@<IP> \
  'mkdir -p ~/lab && tar xzf /tmp/java4shell-lab.tgz -C ~/lab && ~/lab/deploy/run-on-instance.sh'
```

`ec2-user` applies to Amazon Linux. On Ubuntu/Debian use `ubuntu`; on Rocky/Alma use
`rocky`/`almalinux`.

If you see `permission denied ... docker.sock`, run `newgrp docker` or reconnect
SSH (the script also tries `sudo -n` automatically).

The script aborts with status 2 if the CPU lacks any of the four flags, before
spending any time.

## Option 2: Terraform (AWS)

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars   # edit key_name and allowed_cidr
terraform init && terraform plan
terraform apply
```

Then copy the package and run it as in option 1.

The security group opens **only SSH**, and only from your `/32`. Port 8080 is not
opened: the target publishes on `127.0.0.1:8080` inside the instance.

### Instance types

| Type | CPU | AVX-512 VBMI |
|---|---|---|
| `c6i.large` / `m6i.large` | Ice Lake | yes |
| `c7i.large` / `m7i.large` | Sapphire Rapids | yes |
| `c7a` / `m7a` | EPYC Genoa | yes |
| `t3`, `t2`, `m5` | n/a | **no** |

`c6i.large` in `us-east-1` costs about US$ 0.085/h. Use it for a few hours and
destroy it.

## What the script does

| Step | Check |
|---|---|
| 1 | Gate on the 4 flags; aborts if any is missing |
| 2 | JDK version and effective `UseAVX`/`UseBASE64Intrinsics` |
| 3 | Target build (`eclipse-temurin:17.0.6_10-jdk`) |
| 4 | Bounded 129-byte PoC: expects `REPRODUCED` (62 bytes OOB) |
| 5 | One shot on `/decode-exact` (129 bytes); container state and `hs_err_pid` |
| 6 | Restart with `-XX:-UseBASE64Intrinsics`; decoding keeps working |
| 7 | Optional: patched runtime via `PATCHED_IMAGE` |
| 8 | `evidence/<timestamp>/report.md` + raw logs |

## Testing your own image or a fix

Use `JAVA_IMG` to test any runtime image, and `PATCHED_IMAGE` for the remediation
check:

```bash
JAVA_IMG=<your-jdk-image> ./deploy/run-on-instance.sh
PATCHED_IMAGE=eclipse-temurin:17.0.21.1_11-jdk ./deploy/run-on-instance.sh
```

A patched Temurin tag was not yet published on Docker Hub as of 2026-11-18 (the
available tags stop at `17.0.21_9`, which is vulnerable). Meanwhile:

- negative control: `-XX:-UseBASE64Intrinsics` (step 6);
- or build an image from the official Oracle/Corretto `17.0.21.1` tarball and pass
  it as `PATCHED_IMAGE`.

## Expected result on eligible hardware

```
bounded PoC ......... REPRODUCED  (changed=160, window=[96,159], OOB=62)
/decode-exact 129 ... negative victim_len; JVM crashes (DoS)
+ hs_err_pid ........ SIGSEGV in G1 while walking the corrupted header
workaround .......... victim_len=256 / invalid base64, no corruption
```

Do not expect RCE: the write has fixed content and the full chain is not public.

## Cleanup

```bash
cd deploy/terraform && terraform destroy
```

Confirm in the cloud console that the instance and the security group are gone.
