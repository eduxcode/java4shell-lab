import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Instrumented target for CVE-2026-114938.
 *
 * POST /decode       realistic path: Base64.getDecoder().decode(String).
 *                    The JDK allocates the array with the exact size, so the OOB write
 *                    lands in the neighboring heap (it can corrupt/crash the JVM).
 * POST /decode-safe  same decoding into a 4096-byte buffer: safe.
 * GET  /health       runtime + counters, shown in the target pane.
 */
public class DecodeServer {

    static final Base64.Decoder DEC = Base64.getDecoder();
    static final AtomicLong OK = new AtomicLong();
    static final AtomicLong BAD = new AtomicLong();
    static final AtomicLong OOB = new AtomicLong();
    static volatile long sink;
    static volatile Object HOLD;   // prevents scalar replacement of the victim
    static long startedAt;

    public static void main(String[] args) throws Exception {
        startedAt = System.currentTimeMillis();
        warmup(Integer.getInteger("warmup", 200_000));

        int port = Integer.getInteger("port", 8080);
        HttpServer srv = HttpServer.create(new InetSocketAddress(port), 0);

        srv.createContext("/health", ex -> {
            String j = "{\"runtime\":\"" + System.getProperty("java.runtime.version")
                    + "\",\"vm\":\"" + System.getProperty("java.vm.name")
                    + "\",\"arch\":\"" + System.getProperty("os.arch")
                    + "\",\"uptime_ms\":" + (System.currentTimeMillis() - startedAt)
                    + ",\"ok\":" + OK.get() + ",\"bad\":" + BAD.get()
                    + ",\"total\":" + (OK.get() + BAD.get()) + "}";
            send(ex, 200, j);
        });

        srv.createContext("/decode", ex -> {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { send(ex, 405, "POST only"); return; }
            String in = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.US_ASCII);
            try {
                byte[] out = DEC.decode(in);          // internal allocation: real OOB in the heap
                OK.incrementAndGet();
                send(ex, 200, "{\"decoded\":" + out.length + "}");
            } catch (IllegalArgumentException e) {
                BAD.incrementAndGet();
                send(ex, 400, "{\"error\":\"invalid base64\"}");
            } catch (Throwable t) {
                send(ex, 500, "{\"error\":\"" + t.getClass().getName() + "\"}");
            }
        });

        /*
         * /decode-exact: same write as decode(String), but with the buffer at
         * the exact size the JDK would allocate and a victim allocated right after.
         * The 64-byte store at data[dp] overruns the header of the next object,
         * making the corruption observable (victim_len != 256) and fatal for the GC.
         */
        srv.createContext("/decode-exact", ex -> {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { send(ex, 405, "POST only"); return; }
            byte[] in = ex.getRequestBody().readAllBytes();
            int len = in.length;
            int paddings = 0;
            if (len >= 2 && in[len - 1] == '=') {
                paddings++;
                if (in[len - 2] == '=') paddings++;
            }
            if (paddings == 0 && (len & 3) != 0) paddings = 4 - (len & 3);
            int exact = 3 * ((len + 3) / 4) - paddings;   // JDK's decodedOutLength

            byte[] dst = new byte[Math.max(exact, 0)];
            byte[] victim = new byte[256];
            Arrays.fill(victim, (byte) 0x33);
            HOLD = victim;                                  // forces heap allocation

            int n = -1;
            String err = null;
            try {
                n = DEC.decode(in, dst);
            } catch (IllegalArgumentException e) {
                err = "invalid base64";
            }
            int vlen = victim.length;                       // header may be corrupted
            int v0 = victim[0] & 0xff;

            if (err == null) OK.incrementAndGet(); else BAD.incrementAndGet();
            send(ex, err == null ? 200 : 400, "{\"decoded\":" + n + ",\"buffer\":" + exact
                    + ",\"victim_len\":" + vlen + ",\"victim0\":" + v0
                    + (err != null ? ",\"error\":\"invalid base64\"" : "") + "}");

            if (vlen != 256 || v0 != 0x33) {
                Thread t = new Thread(() -> {
                    try { Thread.sleep(300); } catch (InterruptedException ignored) { }
                    System.gc();                            // the next GC would find the same
                }, "gc-trigger");
                t.setDaemon(true);
                t.start();
            }
        });

        srv.createContext("/decode-safe", ex -> {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { send(ex, 405, "POST only"); return; }
            byte[] in = ex.getRequestBody().readAllBytes();
            byte[] out = new byte[4096];
            try {
                int n = DEC.decode(in, out);
                OK.incrementAndGet();
                send(ex, 200, "{\"decoded\":" + n + ",\"bounded\":true}");
            } catch (IllegalArgumentException e) {
                BAD.incrementAndGet();
                send(ex, 400, "{\"error\":\"invalid base64\"}");
            }
        });

        srv.setExecutor(Executors.newFixedThreadPool(4));
        srv.start();
        System.out.println("[target] listening on " + port
                + " runtime=" + System.getProperty("java.runtime.version"));
        System.out.println("[target] warmup=" + Integer.getInteger("warmup", 200_000)
                + " decodes (forces C2 compilation of the intrinsic)");
    }

    /**
     * Warms up the decoder until C2 selects the optimized path.
     * It deliberately uses 192 characters: the AVX-512 stub is only chosen for
     * inputs with length > 128; warming up with 64 does not exercise the real path.
     */
    static void warmup(int iters) {
        byte[] valid = "A".repeat(192).getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[4096];
        long acc = 0;
        for (int i = 0; i < iters; i++) {
            acc += DEC.decode(valid, out);
        }
        sink = acc;
    }

    static void send(HttpExchange ex, int code, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }
}
