package crypto;

import java.math.BigInteger;

public class ECPoint {
	private BigInteger x;
	private BigInteger y;
	
	public ECPoint() {
	}
	
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
	
	public String toString() {
		return "x: " + x + 
			 "\ny: " + y;
	}
	public String toString(int base) {
		return " x: " + x.toString(base) + 
			 "\n y: " + y.toString(base);
	}
}
