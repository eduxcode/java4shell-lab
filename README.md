# Laboratório CVE-2026-114938 (Java4Shell)

Reprodução **local, sem AWS**, da corrupção de heap no intrinsic Base64 do OpenJDK
HotSpot. Usa o Intel SDE para emular AVX-512 VBMI, porque o hardware desta máquina
não possui essas instruções.

Tudo roda local: o alvo escuta apenas em `127.0.0.1:8080`.

- **Harness, alvo instrumentado, oráculo e método:** eduxcode (github.com/eduxcode)
- **Primitiva do gatilho:** Quang Luong / Calif.io (advisory público CVE-2026-114938)

```bash
git clone https://github.com/eduxcode/java4shell-lab
cd java4shell-lab
./demo/setup-sde.sh
./demo/run-demo.sh
```

> **Uso educacional e defensivo.** Rode apenas em máquinas suas ou com
> autorização explícita. O alvo escuta somente em `127.0.0.1`.

---

## 1. Fatos verificados em fonte primária

| Item | Fonte |
|---|---|
| CVE publicada em 2026-11-17 21:32 UTC pelo Oracle (secalert) | MITRE CVE record |
| CWE-122, componente `hotspot/compiler` | NVD / Corretto changelog |
| CVSS 3.1 = **8.1** (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`) | NVD |
| CVSS 4.0 = **9.2** | Calif.io |
| SSVC (CISA): `exploitation: none`, `automatable: no` | NVD (ADP) |
| Afetados (Oracle): `8u511b33-perf`, `17.0.21.0.3`, `21.0.13.0.3`, `25.0.5.0.3`, `27.0.1.0.3` | NVD |
| Corrigido: `17.0.21.1`, `21.0.13.1`, `25.0.5.1`, `27.0.1.1`, `8u513` | respins de 2026-11-17 |
| Gate de hardware: x86-64 com `avx512f`, `avx512bw`, `avx512vbmi`, `bmi2` | Calif.io |

### Gatilho: a medição corrige o PoC divulgado

O advisory menciona `64x'A'+'='` / `128x'A'+'='`. Medindo o stub real:
**essas entradas não alcançam o código vetorizado.**

O stub `generate_base64_decodeBlock` só entra no caminho AVX-512 quando
`length > 128` (`cmpl(length, 128); jle L_bruteForce`). Abaixo disso, o loop
escalar decodifica blocos de 4 e a cauda é tratada em Java — sem OOB.

O gatilho correto é **129 bytes** (`128x'A' + '='`):

```
length = 129 -> AVX-512
loop de 64 bytes: 129 -> 65 -> 1   (dp = 48 + 48 = 96)
cauda = 1 byte ('=')
output_size = (1 / 4) * 3 - 1 = -1
bzhiq(mask, -1)  -> 0xffffffffffffffff   (BZHI com index >= 64 nao zera nada)
evmovdqub        -> store de 64 bytes em dp = 96
buffer alocado   -> 3*ceil(129/4) - 1 = 98
resultado        -> 96..159: 62 bytes alem do array
```

Também é necessário `(length % 64) ∈ {1,2,3}` para sobrar uma cauda com `=`.
Com 128 bytes (127 `A` + `=`) a entrada é **válida**, decodifica 95 bytes e não
lança exceção. Com 64/128 `A` + `=`, o stub nem é chamado.

> Um gatilho por JVM: a primeira `IllegalArgumentException` desotimiza o
> `decode0`; chamadas seguintes caem no loop escalar.

## 2. O que no prompt original não procede

| Alegação | Realidade |
|---|---|
| `openjdk:17.0.6` como imagem base | Essa tag **não existe** no Docker Hub (HTTP 404). Use `eclipse-temurin:17.0.6_10-jdk`. |
| `-XX:UseAVX=2` é o workaround | Existe, mas o switch preciso é **`-XX:-UseBASE64Intrinsics`**. Em CPU sem AVX-512 o `UseAVX` já é `2` por padrão. |
| "RCE deve ser executado" com `exploit.py --cmd id` | **Não procede.** Ver seções 3 e 9. |
| "62 **ou 63** bytes" | Para o gatilho de 129 bytes são **62** bytes. |
| "Spring Boot com Spring Security é necessário" | Não. Qualquer caminho que decodifique Base64 controlado pelo atacante serve. |
| OOB write basta para RCE | Não. A escrita tem conteúdo fixo e a cadeia completa não é pública. |

## 3. O repositório `Ghost-Bx1/java-exploits` não entrega RCE

Analisado estaticamente (`exploit.py`, 1038 linhas). Não foi executado.

- O advisory diz que as cadeias específicas ficam privadas e que **não há exploit universal**.
- `_build_overwrite_payload()` assume que os 64 bytes do spill são escolhidos pelo atacante.
  Não são: o conteúdo é o resultado da decodificação — no gatilho, `0x69 0xa6 0x9a` repetido.
- Não existe primitiva de grooming. O "pós-exploit" cai em **SSTI** (Thymeleaf) — outra falha.
- Usa gatilho de 32 chars, que nem passa do gate de 128 bytes.

Conclusão: é um scanner com heurística de crash + fallback de SSTI, não um exploit
de Java4Shell.

## 4. Hardware, QEMU e Intel SDE

Host: **Intel i5-8500 (Coffee Lake)** — sem `avx512f/bw/vbmi`, só `bmi2`.

| Caminho | Resultado |
|---|---|
| Nativo | impossível: a JVM nunca seleciona o intrinsic (`UseAVX=2`) |
| QEMU TCG | `TCG doesn't support requested feature ... avx512vbmi`; `vpermb` → SIGILL |
| **Intel SDE 10.13.1** | **funciona**: emula VBMI, reescreve CPUID e a JVM reporta `UseAVX=3` |

Verificação sob SDE:

```
$ sde64 -icx -- jdk/bin/java -XX:+PrintFlagsFinal -version | grep UseAVX
     intx UseAVX = 3 {ARCH product} {default}
```

O SDE é gratuito (Intel Simplified Software License) e não exige cloud.
O `demo/setup-sde.sh` baixa e configura tudo; o JDK 17.0.21 é extraído da imagem
Docker que o laboratório já usa.

## 5. Como rodar (sem AWS)

```bash
# uma vez: baixa o SDE, extrai o JDK e compila
./demo/setup-sde.sh

# gravação em dois painéis (tmux)
./demo/run-demo.sh

# ou gravando com asciinema
./demo/record.sh
```

Dois terminais manuais:

```bash
# Terminal 1 (alvo)
./demo/target.sh
# Terminal 2 (atacante), depois do "NO AR"
./demo/attacker.sh
```

Teste não interativo de ponta a ponta:

```bash
./run-lab.sh
```

Roteiro de gravação e o que observar em cada painel: `demo/README.md`.

## 6. Resultado observado nesta máquina (SDE)

```
oraculo ......................... [HIT] 128x'A'+'=' len=129 buffer=98
                                  cauda=[96,159] OOB=62
POST /decode-exact .............. http=400
                                  {"buffer":98,"victim_len":-1700370022,"victim0":105}
alvo ............................ SIGSEGV em G1RegionMarkStatsCache::add_live_words
                                  hs_err_pid capturado
```

O `victim_len` negativo é a prova visual: o header do objeto alocado logo após o
buffer foi sobrescrito pelos 62 bytes. O `System.gc()` seguinte encontra o heap
inconsistente e a JVM morre — um GC real faria o mesmo.

## 7. Estrutura

```
target/DecodeServer.java   alvo instrumentado (/decode, /decode-exact, /decode-safe, /health)
target/Dockerfile          eclipse-temurin:17.0.6_10-jdk (ARG BASE_IMAGE para o teste patch)
poc/Oracle.java            j4s-oracle: deriva o gatilho e a janela OOB (autoral)
poc/MaskUnderflow.java     causa raiz em Java puro (roda em qualquer CPU)
poc/Base64Trigger.java     PoC bounded de 129 bytes (um processo por comprimento)
demo/                      setup do SDE, dois painéis, roteiro e gravação
deploy/                    pacote opcional para instância com AVX-512 nativo
run-lab.sh                 teste não interativo de ponta a ponta
CREDITS.md                 atribuição do achado e do harness
```

## 8. Mitigação e remediação

1. **Imediato:** `-XX:-UseBASE64Intrinsics`.
   Validar com carga real: o decode continua correto, apenas mais lento.
2. **Definitivo:** atualizar para `17.0.21.1`, `21.0.13.1`, `25.0.5.1`, `27.0.1.1` ou `8u513`.
3. **Verificação pós-patch:** repetir o oráculo em AVX-512 (ou SDE) → `changed=0` /
   `NOT REPRODUCED`.
4. **Não confiar em:** validação de tamanho, rate limit ou WAF. O payload usa apenas
   caracteres Base64 e termina em `=`; é indistinguível de tráfego legítimo malformado.

## 9. Detecção

- Bodies/headers Base64 com **129 bytes** (ou `len > 128` e `len % 64 ∈ {1,2,3}`)
  terminando em `=`.
- Picos de `400 invalid base64` seguidos de restart de JVM ou `hs_err_pid*.log`.
- `IllegalArgumentException` em `java.util.Base64` no log da aplicação.
- Serviços que decodificam Base64 e não estão no range corrigido são prioridade máxima,
  independentemente de SSVC `exploitation: none`.

## 10. Instância com AVX-512 (opcional)

Sem AWS, use qualquer máquina Ice Lake+/Zen 4+, ou uma free tier de GCP/Azure.
O pacote `deploy/` continua disponível para isso; ele não é necessário para gravar
a demo nesta máquina. Ver `deploy/README.md`.

## 11. Licença e uso responsável

Código sob **MIT** (ver `LICENSE`). A primitiva do CVE pertence aos pesquisadores
originais e está atribuída em `CREDITS.md`.

Este material é **educacional e defensivo**. Use apenas em sistemas seus ou com
autorização por escrito. O laboratório não implementa RCE e não deve ser
apresentado como exploit armado.
