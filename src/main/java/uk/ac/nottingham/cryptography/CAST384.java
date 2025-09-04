package uk.ac.nottingham.cryptography;

/**
 * Implementation of CASTCipher that encrypts and decrypts using the
 * CAST-384 algorithm.
 */
public class CAST384 extends CASTCipher {

    public CAST384() {
        super(192, 384);
    }
    @Override
    public void initialise(byte[] key) {
        K = generateRoundKeys(generateScheduleKeys(12,4),key,12,4);
    }

    @Override
    public CASTKeySet generateScheduleKeys(int roundCount, int dodecadCount) {
        // Initialise variable
        int i; // loop counter
        int Cm = 0x5A827999;
        int Cr = 19;

        // Arrays
        int [] Tm = new int[dodecadCount * roundCount * 12];
        int [] Tr = new int[dodecadCount * roundCount * 12];
        for ( i = 0; i < 12*roundCount*dodecadCount; i++ ) {
                Tm[i] = Cm; // i * 12 because needs 1 to jump by 12 every step
                Cm += 0x6ED9EBA1; // Java handles mod 2^32

                Tr[i] = Cr;
                Cr = (Cr + 17) % 32;
        }
        return new CASTKeySet(Tm, Tr);
    }

    @Override
    public CASTKeySet generateRoundKeys(CASTKeySet T, byte[] key, int roundCount, int dodecadCount) {
        // Initialise variable
        int i; // Loop counter
        int j; // Loop counter

        // Arrays
        int [] k = bytesToInts(key);
        int [] Km = new int[roundCount*6];
        int [] Kr = new int[roundCount*6];
        for ( i = 0; i < roundCount; i ++){
            for ( j = 0; j < dodecadCount; j++){
               dodecad(k,T.getM(), T.getR(),((i*dodecadCount + j)*12));
            }
            int index = i*6;
            Km[index] = k[11];
            Km[1+index] = k[9];
            Km[2+index] = k[7];
            Km[3+index] = k[5];
            Km[4+index] = k[3];
            Km[5+index] = k[1];

            Kr[index] = k[0] & 0xff % 32;
            Kr[1+index] = k[2] & 0xff % 32;
            Kr[2+index] = k[4] & 0xff % 32;
            Kr[3+index] = k[6] & 0xff % 32;
            Kr[4+index] = k[8] & 0xff % 32;
            Kr[5+index] = k[10] & 0xff % 32;
        }
        return new CASTKeySet(Km, Kr);
    }

    @Override
    public int f1 (int d, int Km, int Kr) {
        int I = rotatel( d + Km,Kr); // Left rotation

        return (((S1[( (I >>> 24)) & 0xff] ^ S2[((I >>> 16)) & 0xff]) - S3[(I >>> 8) & 0xff] + S4[I & 0xff]));
    }

    @Override
    public int f2 (int d, int Km, int Kr) {
        int I = rotatel(d ^ Km,Kr); // Left rotation

        return ((((S1[(I >>> 24) & 0xff] - S2[(I >>> 16) & 0xff]) + S3[(I >>> 8) & 0xff]) ^ S4[I & 0xff]));
    }

    @Override
    public int f3 (int d, int Km, int Kr) {
        int I = rotatel(Km - d,Kr); // Left rotation

        return ((((S1[(I >>> 24) & 0xff] + S2[(I >>> 16) & 0xff]) ^ S3[(I >>> 8) & 0xff]) - S4[I & 0xff]));
    }

    @Override
    public int f4 (int d, int Km, int Kr) {
        int I = rotatel(Km - d,Kr); // Left rotation

        return ((((S1[(I >>> 24) & 0xff] ^ S2[(I >>> 16) & 0xff]) + S3[(I >>> 8) & 0xff]) - S4[I & 0xff]));
    }

    @Override
    public int f5 (int d, int Km, int Kr) {
        int I = rotatel(Km + d,Kr); // Left rotation

        return ((((S1[(I >>> 24) & 0xff] - S2[(I >>> 16) & 0xff]) ^ S3[(I >>> 8) & 0xff]) + S4[I & 0xff]));
    }

    @Override
    public int f6 (int d, int Km, int Kr) {
        int I = rotatel(Km ^ d,Kr); // Left rotation

        return ((((S1[(I >>> 24) & 0xff] + S2[(I >>> 16) & 0xff]) - S3[(I >>> 8) & 0xff]) ^ S4[I & 0xff]));
    }

    @Override
    public void dodecad(int[] block, int[] Tm, int[] Tr, int idx) {

        block[10] ^= f1(block[11], Tm[idx],Tr[idx]);
        block[9] ^= f2(block[10], Tm[1+idx],Tr[1+idx]);
        block[8] ^= f3(block[9], Tm[2+idx],Tr[2+idx]);
        block[7] ^= f4(block[8], Tm[3+idx],Tr[3+idx]);
        block[6] ^= f5(block[7], Tm[4+idx],Tr[4+idx]);
        block[5] ^= f6(block[6], Tm[5+idx],Tr[5+idx]);
        block[4] ^= f1(block[5], Tm[6+idx],Tr[6+idx]);
        block[3] ^= f2(block[4], Tm[7+idx],Tr[7+idx]);
        block[2] ^= f3(block[3], Tm[8+idx],Tr[8+idx]);
        block[1] ^= f4(block[2], Tm[9+idx],Tr[9+idx]);
        block[0] ^= f5(block[1], Tm[10+idx],Tr[10+idx]);

        block[11] ^= f6(block[0], Tm[11+idx], Tr[11+idx]);
    }

    @Override
    public void hexad(int[] block, int[] Km, int[] Kr, int idx) {
        block[4] ^= f1(block[5], Km[idx],Kr[idx]);
        block[3] ^= f2(block[4], Km[1+idx],Kr[1+idx]);
        block[2] ^= f3(block[3], Km[2+idx],Kr[2+idx]);
        block[1] ^= f4(block[2], Km[3+idx],Kr[3+idx]);
        block[0] ^= f5(block[1], Km[4+idx],Kr[4+idx]);
        block[5] ^= f6(block[0], Km[5+idx],Kr[5+idx]);
    }

    @Override
    public void hexadInv(int[] block, int[] Km, int[] Kr, int idx) { // Indexes reversed
        block[5] ^= f6(block[0], Km[5+idx],Kr[5+idx]);
        block[0] ^= f5(block[1], Km[4+idx],Kr[4+idx]);
        block[1] ^= f4(block[2], Km[3+idx],Kr[3+idx]);
        block[2] ^= f3(block[3], Km[2+idx],Kr[2+idx]);
        block[3] ^= f2(block[4], Km[1+idx],Kr[1+idx]);
        block[4] ^= f1(block[5], Km[idx],Kr[idx]);
    }

    @Override
    public void encrypt(byte[] data) {
        int i;
        int[] ints = bytesToInts(data);
        for ( i = 0; i < 6; i++){
                hexad(ints, K.getM(), K.getR(), i*6); // times 6 so each key set is different, as hexad uses 6 blocks
           }
        for ( i = 6; i < 12; i++){
               hexadInv(ints,K.getM(), K.getR(),i*6);
           }
        System.arraycopy(intsToBytes(ints),0,data,0,data.length);
    }

    @Override
    public void decrypt(byte[] data) {
        int[] ints = bytesToInts(data);
        int i;
        for (i = 0; i < 6; i++) {
            hexad(ints, K.getM(), K.getR(), 66 - (i * 6)); // last index is 72, but can't be 72 long so 66
        }
        for (i = 6; i < 12; i++){
                hexadInv(ints,K.getM(), K.getR(),66 - (i * 6));
        }
        System.arraycopy(intsToBytes(ints),0,data,0,data.length);
    }

    // Helper functions
    int rotatel(int x, int n) {
        return (x << n) | (x >>> (32 - n));
    }

    int[] bytesToInts(byte[] input) {
        int[] array = new int[12];
        int i;
        int lengthLoop = input.length/4;
        for (i = 0; i < lengthLoop; i++) {
            int index = i * 4;
            array[i] = ((input[index] & 0xFF) << 24) | (input[index + 1] & 0xFF) << 16 | (input[index + 2] & 0xFF) << 8
                    | input[index + 3] & 0xFF;
        }
        return array;
    }
    byte[] intsToBytes(int[] input) {
        int lengthInput = input.length;
        byte[] array = new byte[lengthInput * 4];
        int i;
        for (i = 0; i < lengthInput; i++) {
            int outputIndex = i * 4;
            int shift = input[i];

            array[outputIndex + 3] = (byte)shift;
            array[outputIndex + 2] = (byte)((shift & 0x0000FF00) >> 8);
            array[outputIndex + 1] = (byte)((shift & 0x00FF0000) >> 16);
            array[outputIndex] = (byte)((shift & 0xFF000000) >> 24);

        }
        return array;
    }


}

