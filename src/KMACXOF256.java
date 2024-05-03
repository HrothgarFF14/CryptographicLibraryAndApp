/*
Programming Project Practical
Coded by Louis Lomboy, Ahmed Mohamed and Shu-Ren Shen

Taken inspiration from code by Markku-Juhani O. Saarinen <mjos@iki.fi>
https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c


 */

import java.math.BigInteger;
import java.util.Arrays;

public class KMACXOF256 {

    private static final BigInteger[] ROUND_CONSTANTS = initializeRoundConstants();
    private static final int[] KECCAKF_ROTC = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};
    private static final int[] KECCAKF_PILN = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

    private BigInteger[] state;
    private int messageDigestLength;
    private int rateSize;
    private int pt;

    private static BigInteger[] initializeRoundConstants() {
        String[] roundConstantStrings = {
                "0000000000000001", "0000000000008082", "800000000000808A", "8000000080008000",
                "000000000000808B", "0000000080000001", "8000000080008081", "8000000000008009",
                "000000000000008A", "0000000000000088", "0000000080008009", "000000008000000A",
                "000000008000808B", "800000000000008B", "8000000000008089", "8000000000008003",
                "8000000000008002", "8000000000000080", "000000000000800A", "800000008000000A",
                "8000000080008081", "8000000000008080", "0000000080000001", "8000000080008008"
        };
        BigInteger[] roundConstants = new BigInteger[24];
        for (int i = 0; i < 24; i++) {
            roundConstants[i] = new BigInteger(roundConstantStrings[i], 16);
        }
        return roundConstants;
    }


    // The bytepad function pads the input string X with zeros until its length is a multiple of w bytes.
    public byte[] bytepad(byte[] X, int w) {
        // TODO: Implement the bytepad function
        int paddingLength = w - (X.length % w);
        byte[] padded = new byte[X.length + paddingLength];
        for (int i = X.length; i < padded.length; i++) {
            padded[i] = 0;
        }
        return padded;
    }

    // The encode_string function prepends the bit length of the string S to the string itself.
    public byte[] encode_string(byte[] S) {
        // TODO: Implement the encode_string function
        int bitLength = S.length * 8; //calculate the bit length of the string
        byte[] bitLengthBytes = BigInteger.valueOf(bitLength).toByteArray(); //convert the bit length to a byte array

        //create a new byte array with the length of the S plus the length of the bit length bytes
        byte[] encoded = new byte[S.length + bitLengthBytes.length];

        //Copy bitLengthBytes and S into the new array
        System.arraycopy(bitLengthBytes, 0, encoded, 0, bitLengthBytes.length);
        System.arraycopy(S, 0, encoded, bitLengthBytes.length, S.length);

        return encoded;
    }

    /// The left_encode function encodes the integer x as a byte string in a specific format.
    public static byte[] left_encode(long x) {
        if (x < 0 || x >= Math.pow(2, 2040)) {
            throw new IllegalArgumentException("Value of x is out of valid range.");
        }
        int n = 1;
        long power = 1;
        while (power <= x) {
            n++;
            power *= 256;
        }
        byte[] encode = new byte[n + 1];
        encode[0] = enc8(n);
        for (int i = 1; i <= n; i++) {
            byte xi = (byte) ((x >> (8 * (n - i))) & 0xFF);
            encode[i] = xi;
        }
        return encode;
    }
    /// enc8 For an integer i ranging from 0 to 255, enc8(i) is the byte encoding of i,
    //  with bit 0 being the low-order bit of the byte.
    public static byte enc8(int i) {
        if (i < 0 || i > 255) {
            throw new IllegalArgumentException("Input i must be in the range [0, 255].");
        }
        return (byte) i;
    }

    // The right_encode function also encodes the integer x as a byte string in a specific format.
    public byte[] right_encode(BigInteger x) {
        // TODO: Implement the right_encode function
        return null;
    }

    // The keccakf function is the main part of the KMACXOF256 function. It involves several steps,
    // including the θ, ρ, π, χ, and ι transformations, which involve various bitwise operations and permutations.
    public void keccakf() {
        // TODO: Implement the Keccak core algorithm
    }

    // The init function initializes the state to zero, sets the message digest length and rate size, and resets the pointer.
    public void init(int mdlen) {
        // TODO: Implement the init function
        state = new BigInteger[25];
        Arrays.fill(state, BigInteger.ZERO);
        messageDigestLength = mdlen;
        rateSize = 200 - 2 * mdlen;
        pt = 0;
    }

    // The update function absorbs each block of data into the state.
    public void update(byte[] data) {
        // TODO: Implement the update function
        int j = pt;
        for (int i = 0; i < data.length; i++) {
            state[j++] = state[j++].xor(BigInteger.valueOf(data[i]));
            if (j >= rateSize) {
                keccakf();
                j = 0;
            }
        }
        pt = j;
    }

    // The finalHash function applies padding and then extracts the output.
    public byte[] finalHash() {
        // TODO: Implement the final function
        return null;
    }

    // The KMACXOF256 function initializes the state, absorbs the input, and extracts the output.
    public byte[] KMACXOF256(byte[] in, int mdlen) {
        // TODO: Implement the KMACXOF256 function
        init(mdlen);
        update(in);
        return finalHash();
    }

    // The xof function switches to the squeezing phase.
    public void xof() {
        state[pt] = state[pt].xor(BigInteger.valueOf(0x1F));
        state[rateSize - 1] = state[rateSize - 1].xor(BigInteger.valueOf(0x80));
        keccakf();//Maybe wrong
        pt = 0;
    }

    // The out function extracts the output.
    public void out(byte[] out, int len) {
        // TODO: Implement the out function
    }
}
