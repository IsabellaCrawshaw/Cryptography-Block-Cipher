package uk.ac.nottingham.cryptography;

import java.util.Arrays;

public class Main {

    public static void main(String[] args) {
        // Example: create cipher with a zero key, encrypt a zero block
        CASTCipher c384 = new CAST384();
        c384.initialise(new byte[48]);
        c384.encrypt(new byte[24]);

        // You can add testing code here
    }
}

