import java.math.BigInteger;
import java.security.KeyPair;

import static java.math.BigInteger.ONE;

public class Ed448 {
    private static final BigInteger p = BigInteger.valueOf(2).pow(448).subtract(BigInteger.valueOf(2).pow(224)).subtract(ONE);
    private static final BigInteger d = BigInteger.valueOf(-39081);

    private BigInteger x;
    private BigInteger y;

    // Constructor for a curve point given its x and y coordinates
    public Ed448(BigInteger x, BigInteger y) {
        this.x = x.mod(p);
        this.y = y.mod(p);
        if (!onCurve()) {
            throw new IllegalArgumentException("Point is not on the curve");
        }
    }

    /**
     * Represents an elliptic curve public key.
     */
    public class ECPublicKey {
        // TODO: Define the public key parameters and methods
    }

    /**
     * Represents an elliptic curve private key.
     */
    public class ECPrivateKey {
        // TODO: Define the private key parameters and methods
    }
    // Constructor for the neutral element (0, 1)
    public void neutralPoint() {
        this.x = BigInteger.ZERO;
        this.y = ONE;
    }

    // Check if the point is on the curve
    private boolean onCurve() {
        BigInteger left = (x.modPow(BigInteger.TWO, p).add(y.modPow(BigInteger.TWO, p)));
        BigInteger right = ONE.add(d).multiply((x.modPow(BigInteger.TWO, p).add(y.modPow(BigInteger.TWO, p))));
        return left.equals(right);
    }

    // Compare two points for equality
    @Override
    public boolean equals(Object obj) {
        Ed448 temp = (Ed448) obj;
        return x.equals(temp.x) && y.equals(temp.y);
    }

    // Get the opposite of a point (x, y) -> (-x, y)

    public Ed448 oppositePoint() {
        return new Ed448(x.negate(), y);
    }

    // Add two points using the Edwards point addition formula
    public Ed448 add(Ed448 temp) {
        BigInteger x1 = this.x;
        BigInteger y1 = this.y;
        BigInteger x2 = temp.x;
        BigInteger y2 = temp.y;

        BigInteger x3 = (x1.multiply(y2).add(y1.multiply(x2))).divide((ONE).add((d).multiply((x2.multiply(y1).multiply(y2)))));
        BigInteger y3 = (y1.multiply(y2).subtract((x1.multiply(x2))).divide((ONE).subtract((d).multiply(x1).multiply((x2.multiply(y1).multiply(y2))))));

        return new Ed448(x3, y3);
    }

    public  Ed448 P = new Ed448(BigInteger.ZERO, BigInteger.ZERO);
    //ToDO  implement P

    // Scalar multiplication using the double-and-add algorithm
    public Ed448 scalarMultiply(BigInteger k) {
        Ed448 V = P;
        for (int i = k.bitLength() - 1; i >= 0; i--) {
            V = V.add(V);
            if (k.testBit(i)) {
                V = V.add(P);
            }
        }
        return V;
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }

    /**
     * Generates a public and private key pair for the elliptic curve cryptography
     * @return A KeyPair object containing the public and private keys
     */
    public static KeyPair generateKeyPair() {
        return null;
    }

    /**
     * Encrypts a plaintext message using a given public key.
     * @param publicKey The public key to use for encryption.
     * @param plaintext The plaintext message to encrypt.
     * @return The encrypted message.
     */
    public static byte[] encrypt(ECPublicKey publicKey, byte[] plaintext) {
        return null;
    }

    /**
     * Decrypts a ciphertext message using a given private key.
     * @param privateKey The private key to use for decryption.
     * @param ciphertext The ciphertext message to decrypt.
     * @return The decrypted message.
     */
    public static byte[] decrypt(ECPrivateKey privateKey, byte[] ciphertext) {
        return null;
    }

    /**
     * Generates a digital signature for a given message using a given private key.
     * @param privateKey The private key to use for signing.
     * @param message The message to sign.
     * @return The digital signature.
     */
    public static byte[] sign(ECPrivateKey privateKey, byte[] message) {
        // TODO: Implement digital signature generation
        return null;
    }

    /**
     * Verifies a digital signature for a given message using a given public key.
     * @param publicKey The public key to use for verification.
     * @param message The message for which the signature was generated.
     * @param signature The digital signature to verify.
     * @return true if the signature is valid, false otherwise.
     */
    public static boolean verify(ECPublicKey publicKey, byte[] message, byte[] signature) {
        // TODO: Implement digital signature verification
        return false;
    }

    /**
     * Compute a square root of v mod p with a specified least-significant bit
     * if such a root exists.
     *
     * @param v the radicand.
     * @param p the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     * if such a root exists, otherwise null.
     */
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }


}
