/*
Programming Project Practical
Coded by Louis Lomboy, Ahmed Mohamed and Shu-Ren Shen

Taken inspiration from code by Markku-Juhani O. Saarinen <mjos@iki.fi>
https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c


 */

import java.math.BigInteger;
import java.util.Arrays;

public class KMACXOF256 {

    private byte[] inData;
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

    /**
     * Pads the input string X with zeros until its length is a multiple of w bytes.
     * @param X The input string to be padded
     * @param w the desired length of the padded string
     * @return the padded string
     */
    public byte[] bytepad(byte[] X, int w) {
        int paddingLength = w - (X.length % w);
        byte[] padded = new byte[X.length + paddingLength];
        for (int i = X.length; i < padded.length; i++) {
            padded[i] = 0;
        }
        return padded;
    }

    // The encode_string function prepends the bit length of the string S to the string itself.

    /**
     * Prepends the bit length of the string S to the string itself.
     * @param S The input string to be encoded
     * @return the encoded string
     */
    public byte[] encode_string(byte[] S) {
        int bitLength = S.length * 8; //calculate the bit length of the string
        byte[] bitLengthBytes = BigInteger.valueOf(bitLength).toByteArray(); //convert the bit length to a byte array

        //create a new byte array with the length of the S plus the length of the bit length bytes
        byte[] encoded = new byte[S.length + bitLengthBytes.length];

        //Copy bitLengthBytes and S into the new array
        System.arraycopy(bitLengthBytes, 0, encoded, 0, bitLengthBytes.length);
        System.arraycopy(S, 0, encoded, bitLengthBytes.length, S.length);

        return encoded;
    }

    /**
     * Returns CSHAKE (in terms of Keccak and SHAKE256) of the given goodies
     *
     * @param X The data for KECCAK to shake up.
     * @param L The length of the digest desired to be returned.
     * @param N Diversification string to augment output.
     * @param S Diversification string to augment output.
     * @return
     */
    public void cSHAKE256(byte[] X, int L, String N, String S){
        // Convert the diversification strings to byte arrays
        char[] flex = N.toCharArray();
        byte[] x1 = new byte[flex.length];
        for (int i = 0; i < flex.length; i++){
            x1[i] = (byte)flex[i];
        }
        char[] flex2 = S.toCharArray();
        byte[] x2 = new byte[flex2.length];
        for (int i = 0; i < flex2.length; i++) {
            x2[i] = (byte)flex2[i];
        }

        // Encode the diversification strings
        byte[] n = encode_string(x1);
        byte[] s = encode_string(x2);

        // Combine the encoded diversification strings
        byte[] newX = new byte[n.length + s.length];
        for (int index = 0; index < n.length; index++) {
            newX[index] = n[index];
        }

        for (int index = 0; index < s.length; index++) {
            newX[index] = s[index];
        }

        // Pad the combined diversification strings
        byte[] retStart = bytepad(newX, 136);

        // Combine the padded diversification strings with the input data
        byte[] ret = new byte[retStart.length + X.length + 2];

        for (int index = 0; index < retStart.length; index++) {
            ret[index] = retStart[index];
        }
        for (int index = 0; index < X.length; index++) {
            ret[index] = X[index];
        }
        ret[ret.length-2] = 0;
        ret[ret.length-1] = 0;

        // Store the result in the inData field
        inData = ret;
    }
    /// The left_encode function encodes the integer x as a byte string in a specific format.

    /**
     * Encodes the integer x as a byte string in a specific format.
     * @param x The integer to be encoded
     * @return the encoded byte string
     */
    public static byte[] left_encode(int x) {
        String binaryX = Integer.toBinaryString(x);
        String paddedX = multipleEight(binaryX);
        String length = Integer.toBinaryString(binaryX.length());
        String paddedL = multipleEight(length);
        String encodedString = paddedL + paddedX;


        byte[] encodedBytes = new byte[encodedString.length() / 8];
        for (int i = 0; i < encodedString.length(); i += 8) {
            String byteString = encodedString.substring(i, i + 8);
            encodedBytes[i / 8] = (byte) Integer.parseInt(byteString, 2);
        }

        return encodedBytes;
    }

    /// enc8 For an integer i ranging from 0 to 255, enc8(i) is the byte encoding of i,
    //  with bit 0 being the low-order bit of the byte.

    /**
     * For an integer i ranging as a byte
     * @param i The integer to be encoded
     * @return the encoded byte
     */
    public static byte enc8(int i) {
        if (i < 0 || i > 255) {
            throw new IllegalArgumentException("Input i must be in the range [0, 255].");
        }
        return (byte) i;
    }
    private static String multipleEight(String binaryString) {
        int remainder = binaryString.length() % 8;
        if (remainder != 0) {
            int paddingLength = 8 - remainder;
            StringBuilder zeros = new StringBuilder();
            for (int i = 0; i < paddingLength; i++) {
                zeros.append("0");
            }
            binaryString = zeros.toString() + binaryString;
        }
        return binaryString;
    }


    private static byte[] right_encode(int x) {
        String binaryX = Integer.toBinaryString(x);
        String paddedX = multipleEight(binaryX);
        String length = Integer.toBinaryString(binaryX.length());
        String paddedL = multipleEight(length);
        String encodedString = paddedX + paddedL;

        byte[] encodedBytes = new byte[encodedString.length() / 8];
        for (int i = 0; i < encodedString.length(); i += 8) {
            String byteString = encodedString.substring(i, i + 8);
            encodedBytes[i / 8] = (byte) Integer.parseInt(byteString, 2);
        }
        return encodedBytes;
    }

    // The keccakf function is the main part of the KMACXOF256 function. It involves several steps,
    // including the θ, ρ, π, χ, and ι transformations, which involve various bitwise operations and permutations.
    public void keccakf() {
        // TODO: Implement the Keccak core algorithm
    }

    // The init function initializes the state to zero, sets the message digest length and rate size, and resets the pointer.

    /**
     * Initializes the state to zero, sets the message digest length and rate size, and resets the pointer.
     * @param mdlen The message digest length
     */
    public void init(int mdlen) {
        state = new BigInteger[25];
        Arrays.fill(state, BigInteger.ZERO);
        messageDigestLength = mdlen;
        rateSize = 200 - 2 * mdlen;
        pt = 0;
    }

    // The update function absorbs each block of data into the state.

    /**
     * Absorbs each block of data into the state.
     * @param data The data to be absorbed
     */
    public void update(byte[] data) {
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

    /**
     * Applies padding and then extracts the output.
     * @return the final hash
     */
    public byte[] finalHash() {
        // apply padding
        state[pt] = state[pt].xor(BigInteger.valueOf(0x06));
        state[rateSize - 1] = state[rateSize - 1].xor(BigInteger.valueOf(0x80));
        keccakf();

        // Extract the output
        byte[] output = new byte[messageDigestLength];
        for (int i = 0; i < messageDigestLength; i++) {
            output[i] = state[i].byteValue();
        }
        return output;
    }

    // The KMACXOF256 function initializes the state, absorbs the input, and extracts the output.

    /**
     * Initializes the state, absorbs the input, and extracts the output.
     * @param in The input data
     * @param mdlen The message digest length
     * @return the final hash
     */
    public byte[] KMACXOF256(byte[] in, int mdlen) {
        // TODO: Implement the KMACXOF256 function
        init(mdlen);
        update(in);
        return finalHash();
    }

    // The xof function switches to the squeezing phase.

    /**
     * Switches to the squeezing phase.
     */
    public void xof() {
        state[pt] = state[pt].xor(BigInteger.valueOf(0x1F));
        state[rateSize - 1] = state[rateSize - 1].xor(BigInteger.valueOf(0x80));
        keccakf();//Maybe wrong
        pt = 0;
    }

    // The out function extracts the output.

    /**
     * Extracts the output.
     * @param out The output data
     * @param len The length of the output data
     */
    public void out(byte[] out, int len) {
        for (int i = 0; i < len; i++) {
            if (pt == 0) {
                keccakf();
            }
            out[i] = state[pt].byteValue();
            pt = (pt + 1) % rateSize;
        }
    }
}
