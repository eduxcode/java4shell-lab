# Créditos e proveniência

## Descoberta e pesquisa original

- **Quang Luong** — descoberta, write-up e cadeias de exploração.
- **Calif.io** — divulgação de CVE-2026-114938 ("Java4Shell"), advisory técnico
  e PoC de referência.
- **Jenish Rakholiya** — melhoria do exploit.
- **Oracle** — CNA do CVE e correção (respsins de 2026-11-17).

A primitiva usada neste laboratório o underflow em `bzhiq`/`evmovdqub` no
tratamento da cauda do intrinsic Base64 é derivada desse trabalho publicado.
Ela é reproduzida aqui com atribuição.

## Trabalho autoral deste repositório

**eduxcode** — https://github.com/eduxcode

### 1. Correção empírica do gatilho

O advisory menciona `64x'A'+'='` e `128x'A'+'='`. Medindo o stub
`generate_base64_decodeBlock` do HotSpot, essas entradas **não alcançam o
código vetorizado**: o gate é `length > 128`, e abaixo disso o loop escalar
trata a cauda em Java.

Este repositório deriva e valida o gatilho que realmente dispara:

- **129 bytes** (`128x'A' + '='`);
- condição geral: `length > 128` e `length % 64 ∈ {1,2,3}`;
- janela da store: `dp = 48 * (length / 64)`, 64 bytes;
- buffer alocado pela JDK: `3*ceil(length/4) - paddings`;
- resultado: 62 bytes além do buffer de 98 (`dp=96`, store até 159).

Também documenta que **128 bytes** (127 `A` + `=`) é entrada **válida** —
decodifica 95 bytes e não lança exceção, o que explica o falso negativo.

### 2. Instrumentação

- `poc/Oracle.java` — oráculo que deriva o comprimento e a janela, mede
  primeiro/último byte e valida a contagem, em vez de "algo mudou".
- `poc/MaskUnderflow.java` — emulação da aritmética da máscara em Java puro,
  permitindo demonstrar a causa raiz em CPU sem AVX-512.
- `target/DecodeServer.java` — alvo com contadores por endpoint, caminho
  realista (`/decode`), caminho seguro (`/decode-safe`) e caminho determinístico
  (`/decode-exact`, com vítima alocada após o buffer).
- `demo/` — setup do Intel SDE, fluxo de dois painéis, captura automática de
  `hs_err` e roteiro de gravação.
- `deploy/` — pacote opcional para instância com AVX-512 nativo e Terraform.

### 3. Caminho de execução sem AWS

O host deste laboratório (i5-8500) não possui AVX-512. QEMU TCG não emula as
instruções. O repositório usa o **Intel SDE 10.13.1** (gratuito) para emular
VBMI e reescrever o CPUID, permitindo que a JVM reporte `UseAVX = 3` e execute
o stub real. Isso tornou a reprodução possível em hardware doméstico.

## Por que a atribuição fica

Reivindicar a primitiva como criação própria seria plágio e invalidaria o
material em qualquer revisão técnica. A contribuição defensável é o método de
verificação, a correção do comprimento e a instrumentação e é ela que está
creditada acima.
