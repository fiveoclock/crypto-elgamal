package crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ECC {
	private LibCrypto lib;
	
	private static BigInteger zero = BigInteger.ZERO;
	private static BigInteger one = BigInteger.ONE;
	private static BigInteger two = BigInteger.valueOf(2);
	
	private BigInteger a, b, p;
	
	public ECC(BigInteger a, BigInteger b, BigInteger mod) {
		lib = new LibCrypto();
		this.a = a;
		this.b = b;
		this.p = p;
	}
	
	public void test() {
		ECPoint p = new ECPoint(BigInteger.valueOf(5), BigInteger.valueOf(1));
		ECPoint q = new ECPoint(BigInteger.valueOf(9), BigInteger.valueOf(6));
		
		add(p,q);
	}
	
	public void add(ECPoint P, ECPoint Q) {
		// Berechnung der Steigung der Geraden
		// Geradengleichung: y = kx + d
		// Berechnung von k mittels ( (y2-y1) / (x2-x1) )
		BigInteger y2_y1 = Q.getY().subtract(P.getY());
		BigInteger x2_x1 = Q.getX().subtract(P.getX());
		
		// Division entspricht einer Multiplikation mit dem Inversen
		BigInteger k = x2_x1.modInverse(p).multiply(y2_y1).mod(p);
		
		System.out.println("y2-y1: " +y2_y1);
		System.out.println("y2-y1: " +x2_x1);
		System.out.println("k: " +k);
		
		// Berechnung von R (Rx und Ry)
		// Rx = k² -xp -xq mod p
		
		BigInteger Rx = k.pow(2).subtract(P.getX()).subtract(Q.getX()).mod(p);
		BigInteger Ry = P.getX().subtract(Rx).multiply(k).add(P.getY().negate()).mod(p);
		System.out.println("Rx: " +Rx);
		System.out.println("Ry: " +Ry);
	}
	
	public void doublee(ECPoint P, BigInteger a) {
		// Term 1:
		// ( 3 Px² + a) / (2 Py)
		//     part1    / part2
		BigInteger part1 = BigInteger.valueOf(3).multiply(P.getX().pow(2)).add(a);
		BigInteger part2 = two.multiply(P.getY());
		// Division = Multiplikation mit dem Inversen
		BigInteger term1 = part1.multiply(part2.modInverse(p));
		
		// Berechnung von x3 = ausdruck1² - 2 Px
		BigInteger x3 = term1.pow(2).subtract(two.multiply(P.getX()));
		// Berechnung von y3 = ausdruck1 * (Px - x3) - Py
		BigInteger y3 = term1.multiply(P.getX().subtract(x3)).subtract(P.getY());
		
		System.out.println("x3: " +x3);
		System.out.println("y3: " +y3);
	}
	
	
	
	
}
