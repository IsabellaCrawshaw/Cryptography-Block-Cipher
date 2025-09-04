package cryptography;

/**
 * Implementation of CipherMode that performs encryption and decryption
 * using Counter mode (CTR) with an underlying Cipher.
 */
public class CTRMode extends CipherMode {
    private byte[] nonce;
    private long counter; // long is 64 bits
    double mod =  Math.pow(2,64);
    public CTRMode() {
        super();
    }

    @Override
    public void initialise(Cipher cipher, byte[] key, byte[] nonce) {
        this.cipher = cipher;
        this.cipher.initialise(key);
        this.nonce = nonce;
        this.counter = 0;

    }

    @Override
    public void encrypt(byte[] data) {
            byte[] combination = new byte[nonce.length + longToBytes(counter).length];
            int i;
            int blocks = 0;
            for (i = 0; i < data.length; i++) {
                if (blocks == 0) {
                    byte[] counterInts = longToBytes(counter);
                    System.arraycopy(nonce,0,combination,0,nonce.length);
                    System.arraycopy(counterInts,0,combination,nonce.length,counterInts.length);
                    cipher.encrypt(combination);
                    counter = (long) (counter +(1 % mod));
                }
                data[i] ^= combination[blocks];
                blocks++;
                if(blocks == combination.length)
                    blocks = 0;
            }
    }

    @Override
    public void decrypt(byte[] data) {
        byte[] combination = new byte[nonce.length + longToBytes(counter).length];
        int i;
        int blocks = 0;
        for (i = 0; i < data.length; i++) {
            if (blocks == 0) {
                byte[] counterInts = longToBytes(counter);
                System.arraycopy(nonce,0,combination,0,nonce.length);
                System.arraycopy(counterInts,0,combination,nonce.length,counterInts.length);
                cipher.encrypt(combination);
                counter = (long) (counter +(1 % mod));
            }
            data[i] ^= combination[blocks];
            blocks++;
            if(blocks == combination.length)
                blocks = 0;
        }
    }

    @Override
    public void seek(byte[] counter) {
        long longCount = 0;
        int i;
        for (i = 0; i < counter.length; i++){
            int shiftCount = (counter.length - i - 1)*8;
            long longVal = (counter[i] & 0xFFL) << shiftCount;
            longCount += longVal;

        }
        this.counter = longCount;

    }
    static byte[] longToBytes(long input){
        byte[] array = new byte[8]; // 8 bytes in long
        int i;
        for (i = 0; i < 8; i++){
            array[i] = (byte) (input >>> (8*(7-i))); // int to bytes but shifting by 7*i
        }
        return array;
    }

}

