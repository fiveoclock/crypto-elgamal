package crypto;

import java.math.BigInteger;

public class RSA {
	private static BigInteger one = BigInteger.ONE;
	
	private LibCrypto lib;
	private FileHelper fh;
	private BigInteger p, q, n, nPhi;
	private BigInteger e, d;
	
	public RSA() {
		lib = new LibCrypto();
	}
	
	public RSA(BigInteger e, BigInteger d, BigInteger n) {
		lib = new LibCrypto();
		this.e = e;
		this.d = d;
		this.n = n;
	}
	
	public void generateKeys(int length) {
		System.out.print("Calculating p, ");
		p = lib.generatePrime(length);
		
		System.out.print("q, ");
		q = lib.generatePrime(length);
		
		System.out.print("n, phi(n), ");
		n = p.multiply(q);
		nPhi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		
		System.out.print("e, ");
		// e must be gcd(e, ø(n)) = 1  and  1 < e < ø(n)
		do {
			e = lib.generatePrime(length*2 - length/10 - lib.randInt(length/4));
			System.out.print(".");
		}
		while( (e.compareTo(nPhi) != -1) || (e.gcd(nPhi).compareTo(one) != 0));
		
		System.out.print("d\n");
		d = e.modInverse(nPhi);
		
		//System.out.println("p: " + p);
		//System.out.println("q: " + q);
		System.out.println("n: " + n);
		//System.out.println("nPhi: " + nPhi);
		System.out.println("e: " + e);
		System.out.println("d: " + d);
		
		BigInteger test = e.multiply(d);
		System.out.println("test: " + test.mod(nPhi));
	}
	
	public boolean saveKeys(String prefix) {
		fh = new FileHelper();
		fh.writeBytes(prefix+".e.key", e.toString().getBytes());
		fh.writeBytes(prefix+".d.key", d.toString().getBytes());
		fh.writeBytes(prefix+".n.key", n.toString().getBytes());
		return true;
	}
	
	public boolean loadKeys(String prefix) {
		fh = new FileHelper();
		e = new BigInteger(fh.readLine(prefix+".e.key"));
		d = new BigInteger(fh.readLine(prefix+".d.key"));
		n = new BigInteger(fh.readLine(prefix+".n.key"));
		//System.out.println("n: " + n);
		//System.out.println("e: " + e);
		//System.out.println("d: " + d);
		return true;
	}
	
	public String encrypt(String message) {
		int maxLength = n.bitLength(); // split if message is greater than n
		BigInteger m = new BigInteger(message.getBytes());
		System.out.println("m: " + m);
		BigInteger c = m.modPow(e, n);
		System.out.println("c: " + c.mod(n));
		
		BigInteger dec = c.modPow(d, n);
		System.out.println("m': " + new String(dec.toByteArray()));
		return null;
	}

	public String decrypt(String cipher) {
		int maxLength = n.bitLength();
		BigInteger c = new BigInteger(cipher);
		BigInteger m = c.modPow(d, n);
		System.out.println("m: " + new String(m.toByteArray()));
		return null;
	}
	
}
