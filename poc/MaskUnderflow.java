/**
 * Reproduces the mask arithmetic of HotSpot's x86-64 Base64 intrinsic
 * exactly as described by Quang Luong (Calif.io).
 *
 * It does not depend on AVX-512: it is the same computation in pure Java. It
 * proves the root cause (length underflow) on any CPU.
 */
public final class MaskUnderflow {

    /** Emulates BZHI: clears all bits from position "index" upward. */
    static long bzhiq(long src, long index) {
        if (index < 0 || index >= 64) return src;   // nothing to clear
        if (index == 0) return 0;
        return src & ((1L << index) - 1);
    }

    static void tail(String input) {
        int inLen = input.length();
        long inputMask = bzhiq(-1L, inLen);
        long outLen = (inLen / 4) * 3;

        if (input.charAt(inLen - 1) == '=') {
            outLen -= 1;
            inputMask >>= 1;
            if (inLen >= 2 && input.charAt(inLen - 2) == '=') {
                outLen -= 1;
                inputMask >>= 1;
            }
        }

        long outMask = bzhiq(-1L, outLen);
        boolean allOnes = (outMask == -1L);

        System.out.printf("tail=%-5s inLen=%d outLen=%3d outMask=%016x %s%n",
                "\"" + input + "\"", inLen, outLen, outMask,
                allOnes ? "<-- FULL MASK: 64-byte store" : "");
    }

    public static void main(String[] args) {
        System.out.println("Tail arithmetic of the Base64 intrinsic (HotSpot x86-64)");
        System.out.println("output_len := (inLen / 4) * 3;  if there is a '=', output_len -= 1");
        System.out.println();

        // Final tail of a 65-byte input: 64 x 'A' + '='.
        // The 64-byte block was already consumed; only the '=' remains.
        tail("=");
        tail("==");
        tail("X=");
        tail("XY=");
        tail("X==");
        tail("===");

        System.out.println();
        // Practical effect for the advisory's 65-char input.
        int inLen = 65;                 // 64 x 'A' + '='
        // The JDK allocates (ceil(inLen/4) * 3) - padding = (17*3) - 1 = 50 bytes.
        int bufferLen = (int) Math.ceil(inLen / 4.0) * 3 - 1;
        int destOffset = 48;            // dp after the 64-byte block
        int writeBytes = 64;            // evmovdqub with mask -1
        int writeEnd = destOffset + writeBytes - 1;

        System.out.println("input = 64x'A' + '='  (65 bytes)");
        System.out.println("buffer allocated by the JDK  = " + bufferLen + " bytes");
        System.out.println("destination offset (dp)      = " + destOffset);
        System.out.println("bytes written by the store    = " + writeBytes);
        System.out.println("range written                 = [" + destOffset + ", " + writeEnd + "]");
        System.out.println("bytes inside the buffer       = " + (bufferLen - destOffset));
        System.out.println("bytes OUTSIDE the buffer      = " + (writeEnd - bufferLen + 1));
        System.out.println();

        int oob = writeEnd - bufferLen + 1;
        if (oob == 62) {
            System.out.println("UNDERFLOW CONFIRMED: 62 bytes written past the array");
        } else {
            System.out.println("unexpected: oob=" + oob);
            System.exit(1);
        }
    }
}
