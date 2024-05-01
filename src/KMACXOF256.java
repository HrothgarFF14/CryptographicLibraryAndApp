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
}
