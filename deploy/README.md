# Deploy em instância com AVX-512

Este host (i5-8500) não executa o código vulnerável: falta `avx512vbmi`.
O QEMU também não resolve — o TCG recusa as features.

```
qemu-x86_64: warning: TCG doesn't support requested feature: ...ECX.avx512vbmi [bit 1]
vpermb=SIGILL
```

KVM só ajudaria se o **host** tivesse AVX-512. Então a reprodução real precisa de
hardware Ice Lake+ / Zen 4+.

---

## Opção 1 — instância que você já tem

```bash
# 1) reempacote (sempre que alterar os fontes)
./deploy/package.sh

# 2) copie (troque <IP> e o caminho da chave)
scp -i ~/.ssh/<SUA_CHAVE>.pem deploy/java4shell-lab.tgz ec2-user@<IP>:/tmp/

# 3) execute o laboratorio
ssh -i ~/.ssh/<SUA_CHAVE>.pem ec2-user@<IP> \
  'mkdir -p ~/lab && tar xzf /tmp/java4shell-lab.tgz -C ~/lab && ~/lab/deploy/run-on-instance.sh'
```

`ec2-user` vale para Amazon Linux. Em Ubuntu/Debian use `ubuntu`; em Rocky/Alma, `rocky`/`almalinux`.

Se aparecer `permission denied ... docker.sock`, rode `newgrp docker` ou reconecte o SSH
(o script também tenta `sudo -n` automaticamente).

O script aborta com status 2 se a CPU não tiver os quatro flags — antes de gastar tempo.

## Opção 2 — Terraform (AWS)

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars   # edite key_name e allowed_cidr
terraform init && terraform plan
terraform apply
```

Depois copie o pacote e rode como na opção 1.

O Security Group libera **apenas SSH**, e só do seu `/32`. A porta 8080 não é aberta:
o alvo publica em `127.0.0.1:8080` dentro da instância.

### Tipos de instância

| Tipo | CPU | AVX-512 VBMI |
|---|---|---|
| `c6i.large` / `m6i.large` | Ice Lake | sim |
| `c7i.large` / `m7i.large` | Sapphire Rapids | sim |
| `c7a` / `m7a` | EPYC Genoa | sim |
| `t3`, `t2`, `m5` | — | **não** |

`c6i.large` em `us-east-1` custa cerca de US$ 0,085/h. Use por poucas horas e destrua.

## O que o script faz

| Passo | Verificação |
|---|---|
| 1 | Gate dos 4 flags; aborta se faltar |
| 2 | Versão do JDK e `UseAVX`/`UseBASE64Intrinsics` efetivos |
| 3 | Build do alvo (`eclipse-temurin:17.0.6_10-jdk`) |
| 4 | PoC bounded de 129 bytes: espera `REPRODUCED` (62 bytes OOB) |
| 5 | Um disparo em `/decode-exact` (129 bytes); estado do container e `hs_err_pid` |
| 6 | Restart com `-XX:-UseBASE64Intrinsics`; decode segue funcional |
| 7 | Opcional: runtime corrigido via `PATCHED_IMAGE` |
| 8 | `evidence/<timestamp>/report.md` + logs brutos |

## Teste de remediação

`PATCHED_IMAGE=eclipse-temurin:17.0.21.1_11-jdk ./deploy/run-on-instance.sh`

A tag corrigida do Temurin ainda não estava publicada no Docker Hub em 2026-11-18
(as disponíveis param em `17.0.21_9`, que é vulnerável). Enquanto isso:

- controle negativo: `-XX:-UseBASE64Intrinsics` (passo 6);
- ou use o tarball oficial da Oracle/Corretto `17.0.21.1` como `PATCHED_IMAGE`, se você
  construir a imagem.

## Resultado esperado em hardware elegível

```
PoC bounded ......... REPRODUCED  (changed=160, janela=[96,159], OOB=62)
/decode-exact 129 ... victim_len negativo; JVM cai (DoS)
+ hs_err_pid ........ SIGSEGV no G1 ao percorrer o header corrompido
workaround .......... victim_len=256 / invalid base64, sem corrupção
```

Não espere RCE: a escrita é de conteúdo fixo e a cadeia completa não é pública.

## Limpeza

```bash
cd deploy/terraform && terraform destroy
```

Confirme no console da cloud que a instância e o Security Group sumiram.
