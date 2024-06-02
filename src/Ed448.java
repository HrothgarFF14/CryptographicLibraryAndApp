import java.math.BigInteger;

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
