# Demo em dois terminais — CVE-2026-114938

Kit de gravação curta: um painel mostra o **alvo**, o outro mostra o **atacante**.
Roda **sem AWS**, com AVX-512 VBMI emulado pelo Intel SDE.

- Harness, alvo, oráculo e roteiro: **eduxcode** (github.com/eduxcode)
- Primitiva do gatilho: **Quang Luong / Calif.io** (CVE-2026-114938)

O gatilho é pesquisa publicada. O que é autoral aqui é a instrumentação: o
oráculo que deriva o comprimento correto e a janela exata, os contadores por
endpoint, a vítima alocada após o buffer e a captura automática de `hs_err`.
Mantenha a atribuição no vídeo ela sustenta a credibilidade.

---

## 1. Preparação (uma vez)

```bash
./demo/setup-sde.sh
```

O script:

1. baixa o Intel SDE 10.13.1 (~37 MB) para `demo/.tools/`;
2. extrai o JDK 17.0.21 da imagem `eclipse-temurin:17.0.21_9-jdk` (via Docker);
3. compila alvo e PoCs em `demo/.build/`;
4. confirma que a JVM sob SDE reporta `UseAVX = 3`.

Requisitos: `curl`, `tar`, `docker`, `python3`. Para gravar: `tmux` e,
opcionalmente, `asciinema`.

## 2. Execução

### Opção A — um comando (tmux)

```bash
./demo/run-demo.sh
```

### Opção B — dois terminais

```bash
# Terminal 1 (alvo)
./demo/target.sh

# Terminal 2 (atacante) — espere o "NO AR" no terminal 1
./demo/attacker.sh
```

O alvo sobe em `127.0.0.1:8080`. Nada sai da máquina.

> **Tempo de subida:** sob emulação, a JVM leva ~25–30 s para responder.
> Comece o alvo antes de gravar e corte a espera na edição, ou deixe o painel
> do alvo aparecendo com o banner e os primeiros `health`.

## 3. O que observar em cada painel

### Painel do ALVO (`target.sh`)

| Momento | O que deve aparecer |
|---|---|
| Subida | `modo: Intel SDE (AVX-512 VBMI emulado)` |
| No ar | `NO AR: {"runtime":"17.0.21+9",...}` |
| Baseline | `ok` incrementa, `bad` fica igual |
| Gatilho | `bad` incrementa e o processo morre |
| Queda | `>>> ALVO CAIU` + `SIGSEGV` + `hs_err` na tela |

O contador em `/health` é o sinal visual mais forte: prova que a requisição
chegou na aplicação, não que o vídeo foi cortado.

### Painel do ATACANTE (`attacker.sh`)

| Momento | O que deve aparecer |
|---|---|
| Gate | `AVX-512 VBMI: EMULADO via Intel SDE` |
| Payload | `128x'A' + '=' -> 129 bytes` |
| Baseline | `http=200 {"decoded":48}` |
| Mecanismo | `outMask=ffffffffffffffff` |
| Oráculo | `[HIT] ... buffer=98 ... cauda=[96,159] OOB=62` |
| Disparo | `http=400 ... "victim_len":-1700370022` |
| Queda | `ALVO NAO RESPONDE -> a JVM caiu` |

## 4. Expectativa por cenário

| Cenário | O que o vídeo mostra |
|---|---|
| **Esta máquina + SDE** | `HIT`, `OOB=62`, queda da JVM + `hs_err` |
| Host sem AVX-512 e sem SDE | metodologia + `sem corrupção` |
| Instância com AVX-512 nativo | o mesmo `HIT`, sem emulação |

## 5. O que o vídeo prova — e o que não prova

**Prova:** a aplicação executa o decodificador vetorizado; uma entrada Base64
malformada de 129 bytes provoca a escrita de 64 bytes em `dp=96`, 62 além do
buffer de 98; o header do objeto vizinho é sobrescrito e a JVM cai.

**Não prova:** execução remota de código. A escrita tem conteúdo fixo e a cadeia
completa (writer/reader → Code Cache) não é pública. Titule como
**corrupção de heap reproduzida**, não como RCE. O impacto defensável é:
corrupção de memória determinística + advisory do fornecedor (CVSS 8.1) +
indisponibilidade demonstrada.
