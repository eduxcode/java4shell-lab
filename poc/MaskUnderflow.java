/**
 * Reproduz a aritmetica de mascara do intrinsic Base64 x86-64 do HotSpot
 * exatamente como descrita por Quang Luong (Calif.io).
 *
 * Nao depende de AVX-512: e a mesma conta, em Java puro. Serve para provar
 * a causa raiz (underflow de comprimento) em qualquer CPU.
 */
public final class MaskUnderflow {

    /** Emula BZHI: zera todos os bits a partir da posicao "index". */
    static long bzhiq(long src, long index) {
        if (index < 0 || index >= 64) return src;   // nada a zerar
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
                allOnes ? "<-- MASCARA TOTAL: store de 64 bytes" : "");
    }

    public static void main(String[] args) {
        System.out.println("Aritmetica do tail do intrinsic Base64 (HotSpot x86-64)");
        System.out.println("output_len := (inLen / 4) * 3;  se houver '=', output_len -= 1");
        System.out.println();

        // Cauda final de um input de 65 bytes: 64 x 'A' + '='.
        // O bloco de 64 bytes ja foi consumido; sobra apenas o '='.
        tail("=");
        tail("==");
        tail("X=");
        tail("XY=");
        tail("X==");
        tail("===");

        System.out.println();
        // Efeito pratico para o input de 65 chars do advisory.
        int inLen = 65;                 // 64 x 'A' + '='
        // A JDK aloca (ceil(inLen/4) * 3) - padding = (17*3) - 1 = 50 bytes.
        int bufferLen = (int) Math.ceil(inLen / 4.0) * 3 - 1;
        int destOffset = 48;            // dp apos o bloco de 64 bytes
        int writeBytes = 64;            // evmovdqub com mascara -1
        int writeEnd = destOffset + writeBytes - 1;

        System.out.println("input = 64x'A' + '='  (65 bytes)");
        System.out.println("buffer alocado pela JDK      = " + bufferLen + " bytes");
        System.out.println("offset de destino (dp)       = " + destOffset);
        System.out.println("bytes escritos pela store    = " + writeBytes);
        System.out.println("intervalo escrito            = [" + destOffset + ", " + writeEnd + "]");
        System.out.println("bytes dentro do buffer       = " + (bufferLen - destOffset));
        System.out.println("bytes FORA do buffer         = " + (writeEnd - bufferLen + 1));
        System.out.println();

        int oob = writeEnd - bufferLen + 1;
        if (oob == 62) {
            System.out.println("UNDERFLOW CONFIRMADO: 62 bytes escritos alem do array");
        } else {
            System.out.println("inesperado: oob=" + oob);
            System.exit(1);
        }
    }
}
