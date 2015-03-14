package crypto;

import java.math.BigInteger;

/**
 * @author alex
 * Just a class to compfortly pass points needed for elliptic curve calculations
 */
public class ECPoint {
	private BigInteger x;
	private BigInteger y;
	
	public ECPoint() {}
	
	/**
	 * @param x
	 * @param y
	 * Generates a point with the coordinates x and y
	 */
	public ECPoint(BigInteger x, BigInteger y) {
		this.setX(x);
		this.setY(y);
	}

	public BigInteger getX() {
		return x;
	}
	public void setX(BigInteger x) {
		this.x = x;
	}
	public BigInteger getY() {
		return y;
	}
	public void setY(BigInteger y) {
		this.y = y;
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 * Returns a String with the coordinats x and y of the point
	 */
	public String toString() {
		return toString(10);
	}
	/**
	 * @param base
	 * @return
	 * Returns a String with the coordinats x and y of the point; 
	 * allows hexadecimal representation by specified 16 as base 
	 */
	public String toString(int base) {
		return " x: " + x.toString(base) + 
			 "\n y: " + y.toString(base);
	}
}
