import java.math.BigInteger;

public class Ed448 {
    private static final BigInteger p = BigInteger.valueOf(2).pow(448).subtract(BigInteger.valueOf(2).pow(224)).subtract(BigInteger.ONE);
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
    public neutralPoint() {
        this.x = BigInteger.ZERO;
        this.y = BigInteger.ONE;
    }

    // Check if the point is on the curve
    private boolean onCurve() {
        BigInteger left = (x.modPow(BigInteger.TWO, p).add(y.modPow(BigInteger.TWO, p)));
        BigInteger right = BigInteger.ONE.add(d).multiply((x.modPow(BigInteger.TWO, p).add(y.modPow(BigInteger.TWO, p))));
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

        BigInteger x3 = (x1.multiply(y2).add(y1.multiply(x2))).divide((BigInteger.ONE).add((d).multiply((x2.multiply(y1).multiply(y2)))));
        BigInteger y3 = (y1.multiply(y2).subtract((x1.multiply(x2))).divide((BigInteger.ONE).subtract((d).multiply(x1).multiply((x2.multiply(y1).multiply(y2))))));

        return new Ed448(x3, y3);
    }

    // Scalar multiplication using the double-and-add algorithm
    public  scalarMultiply(BigInteger k) {
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }
}
