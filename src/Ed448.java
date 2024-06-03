import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;

import static java.math.BigInteger.ONE;

public class Ed448 {
    private static final BigInteger p = BigInteger.valueOf(2).pow(448).subtract(BigInteger.valueOf(2).pow(224)).subtract(ONE);
    private static final BigInteger d = BigInteger.valueOf(-39081);
    private static final Ed448 netural = new Ed448(BigInteger.ZERO, ONE);
    private final static BigInteger r = (BigInteger.TWO).pow(446).subtract(
            new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));
    public static Ed448 G = new Ed448(BigInteger.valueOf(8), BigInteger.valueOf(-3).mod(p));


    private BigInteger x;
    private BigInteger y;

    /**
     * Constructor for the Ed448 elliptic curve
     * @param x The x-coordinate of the point
     * @param y The y-coordinate of the point
     * @author Ahmed Mohamed
     */
    public Ed448(BigInteger x, BigInteger y) {
        this.x = x.mod(p);
        this.y = y.mod(p);
        if (!onCurve()) {
            throw new IllegalArgumentException("Point is not on the curve");
        }
    }

    /**
     * Constructor for the neutral element of the curve
     * @author AHmed Mohamed
     */
    public Ed448() {
        this.x = BigInteger.ZERO;
        this.y = ONE;
    }

    /**
     * Generate a public and private key pair for the elliptic curve cryptography
     * @return A KeyPair object containing the public and private keys
     * @Author Shu-Ren Shen
     */
    public class KeyPair{
        private byte[] PublicKey;
        private BigInteger PrivateKey;
        public KeyPair(byte[] PublicKey,BigInteger PrivateKey){
            this.PublicKey = PublicKey;
            this.PrivateKey = PrivateKey;
        }
        public byte[] publicKey() {
            return PublicKey;
        }
        public byte[] privateKey() {
            return PrivateKey.toByteArray();
        }

    }


    /**
     * Check if the point is on the curve
     * @return true if the point is on the curve, false otherwise
     * @Author Ahmed Mohamed and Shu-Ren Shen
     */
    private boolean onCurve() {
        BigInteger left = (x.modPow(BigInteger.TWO, p).add(y.modPow(BigInteger.TWO, p)));
        BigInteger right = ONE.add(d).multiply((x.modPow(BigInteger.TWO, p).add(y.modPow(BigInteger.TWO, p))));
        return left.equals(right);
    }

    /**
     * Override the equals method to compare two Ed448 points
     * @param obj The other Ed448 point to compare to the current point
     * @return true if the two points are equal, false otherwise
     * @author Ahmed Mohamed
     */
    @Override
    public boolean equals(Object obj) {
        Ed448 temp = (Ed448) obj;
        return x.equals(temp.x) && y.equals(temp.y);
    }

    /**
     * Get the opposite point of the current point
     * @return A new Ed448 point that is the opposite of the current point
     * @author Ahmed Mohamed
     */
    public Ed448 oppositePoint() {
        return new Ed448(x.negate(), y);
    }

    /**
     * Add two points on the Ed448 elliptic curve
     * @param temp the other Ed448 point to be added to the current point
     * @return A new Ed448 point that is the result of the addition of the current point and the input point.
     * @author Ahmed Mohamed and Shu-Ren Shen
     *  */
    public Ed448 add(Ed448 temp) {
        BigInteger x1 = this.x;
        BigInteger y1 = this.y;
        BigInteger x2 = temp.x;
        BigInteger y2 = temp.y;

        BigInteger x3 = (x1.multiply(y2).add(y1.multiply(x2))).divide((ONE).add((d).multiply((x2.multiply(y1).multiply(y2)))));
        BigInteger y3 = (y1.multiply(y2).subtract((x1.multiply(x2))).divide((ONE).subtract((d).multiply(x1).multiply((x2.multiply(y1).multiply(y2))))));

        return new Ed448(x3, y3);
    }


    /**
     * Scalar multiplication of a point on the curve
     * @param k The scalar to multiply the point by
     * @return V The point on the curve after scalar multiplication by k
     * @author Shu-Ren Shen
     */
    public Ed448 scalarMultiply(BigInteger k) {
        Ed448 V = netural;
        for (int i = k.bitLength() - 1; i >= 0; i--) {
            V = V.add(V);
            if (k.testBit(i)) {
                V = V.add(netural);
            }
        }
        return V;
    }

    /**
     * Get the x-coordinate of the point
     * @return x The x-coordinate of the point
     * @author Ahmed Mohamed
     */
    public BigInteger getX() {
        return x;
    }

    /**
     * Get the y-coordinate of the point
     * @return y The y-coordinate of the point
     * @author Ahmed Mohamed
     */
    public BigInteger getY() {
        return y;
    }

    /**
     * Generates a public and private key pair for the elliptic curve cryptography
     * @return A KeyPair object containing the public and private keys
     * @author Shu-Ren Shen
     */
    public KeyPair generateKeyPair(byte[] pw) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] s = KMACXOF256.KMACXOF256(pw, "".getBytes(), 448, "SK".getBytes());
        BigInteger V = new BigInteger(s);
        V = (BigInteger.valueOf(4)).multiply(V).mod(r);

        return new KeyPair(s,V);
    }

    /**
     * Encrypts a plaintext message using a given public key.
     * @param V The public key to use for encryption.
     * @param plaintext The plaintext message to encrypt.
     * @return The encrypted message.
     * @author Shu-Ren Shen
     */
    public byte[] encrypt(Ed448 V, byte[] plaintext) {
        Random RAND = new Random();
        BigInteger k = new BigInteger(448, RAND).shiftLeft(2).mod(r);
        Ed448 W = V.scalarMultiply(k);
        Ed448 Z = G.scalarMultiply(k);

        byte[] ka_ke = KMACXOF256.KMACXOF256(W.x.toByteArray(), "".getBytes(), 448 * 2, "PK".getBytes());
        byte[] ka = Arrays.copyOfRange(ka_ke, 0, 56);
        byte[] ke = Arrays.copyOfRange(ka_ke, 56, 112);
        byte[] c = KMACXOF256.KMACXOF256(ke, "".getBytes(), plaintext.length * 8, "PKE".getBytes());
        byte[] t = KMACXOF256.KMACXOF256(ka, plaintext, 448, "PKA".getBytes());
        byte[] leftEncodedC = KMACXOF256.encode_string(c);
        byte[] leftEncodedT = KMACXOF256.encode_string(t);

        return KMACXOF256.appendBytes(KMACXOF256.encode_string(Z.x.toByteArray()),
                KMACXOF256.encode_string(Z.y.toByteArray()), leftEncodedC, leftEncodedT);

    }

    /**
     * Decrypts a ciphertext message using a given private key.
     * @param privateKey The private key to use for decryption.
     * @param ciphertext The ciphertext message to decrypt.
     * @return The decrypted message.
     * @author Louis Lomboy
     */
    public static byte[] decrypt(KeyPair privateKey, byte[] ciphertext) {
        // Extract the cryptogram (Z, c, t) from the ciphertext
        byte[] Z = Arrays.copyOfRange(ciphertext, 0, 56);
        byte[] c = Arrays.copyOfRange(ciphertext, 56, ciphertext.length - 64);
        byte[] t = Arrays.copyOfRange(ciphertext, ciphertext.length - 64, ciphertext.length);

        // Compute s from the passphrase using KMACXOF256
        byte[] s = KMACXOF256.KMACXOF256(privateKey.privateKey(), "".getBytes(), 448, "SK".getBytes());
        BigInteger sNum = new BigInteger(1, s);
        sNum = sNum.multiply(BigInteger.valueOf(4)).mod(r);

        // Compute W from s and Z
        Ed448 W = new Ed448(new BigInteger(1, Z), BigInteger.ZERO).scalarMultiply(sNum);

        // Compute ka and ke from W using KMACXOF256
        byte[] ka_ke = KMACXOF256.KMACXOF256(W.x.toByteArray(), "".getBytes(), 448 * 2, "PK".getBytes());
        byte[] ka = Arrays.copyOfRange(ka_ke, 0, 56);
        byte[] ke = Arrays.copyOfRange(ka_ke, 56, 112);

        // Compute m from c and ke using KMACXOF256 and XOR operation
        byte[] m = new byte[c.length];
        byte[] keStream = KMACXOF256.KMACXOF256(ke, "".getBytes(), c.length * 8, "PKE".getBytes());
        for (int i = 0; i < c.length; i++) {
            m[i] = (byte) (c[i] ^ keStream[i]);
        }

        // Compute t' from ka and m using KMACXOF256
        byte[] tPrime = KMACXOF256.KMACXOF256(ka, m, 448, "PKA".getBytes());

        // Accept if, and only if, t' equals t
        if (Arrays.equals(t, tPrime)) {
            return m;
        } else {
            throw new IllegalArgumentException("Invalid ciphertext");
        }
    }

    /**
     * Generates a digital signature for a given message using a given private key.
     * @param privateKey The private key to use for signing.
     * @param message The message to sign.
     * @return The digital signature.
     * @author Shu-Ren Shen
     */
    public static byte[] sign(KeyPair privateKey, byte[] message) {
        byte[] pw = privateKey.privateKey();
        var s = new BigInteger(KMACXOF256.KMACXOF256(pw, "".getBytes(), 448, "SK".getBytes()))
                .shiftLeft(2).mod(r);
        BigInteger k = new BigInteger(KMACXOF256.KMACXOF256(s.toByteArray(), message, 448, "N".getBytes()))
                .shiftLeft(2).mod(r);
        var U = G.scalarMultiply(k);
        byte[] h = new BigInteger(
                KMACXOF256.KMACXOF256(U.x.toByteArray(), message, 448, "T".getBytes())).mod(r).toByteArray();
        byte[] z = (k.subtract((new BigInteger(h)).multiply(s))).mod(r).toByteArray();
        // signature: (h, z)
        return KMACXOF256.appendBytes(KMACXOF256.encode_string(h), KMACXOF256.encode_string(z));
    }

    /**
     * Verifies a digital signature for a given message using a given public key.
     * @param publicKey The public key to use for verification.
     * @param message The message for which the signature was generated.
     * @param signature The digital signature to verify.
     * @return true if the signature is valid, false otherwise.
     * @author Louis Lomboy
     */
    public static boolean verify(KeyPair publicKey, byte[] message, byte[] signature) {
        byte[] h = Arrays.copyOfRange(signature, 0, 56);
        byte[] z = Arrays.copyOfRange(signature, 56, signature.length);
        Ed448 U = G.scalarMultiply(new BigInteger(1, z))
                .add(new Ed448(new BigInteger(1, publicKey.publicKey()), BigInteger.ZERO)
                        .scalarMultiply(new BigInteger(1, h)));
        byte[] hPrime = KMACXOF256.KMACXOF256(U.x.toByteArray(), message, 448, "T".getBytes());

        return Arrays.equals(h, hPrime);
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
     * @author Shu-Ren Shen
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