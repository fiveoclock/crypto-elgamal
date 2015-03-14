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
	
	/**
	 * @param length
	 * Generates random keys for en- and decryption
	 */
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
	
	/**
	 * @param prefix
	 * @return
	 * Saves the generated keys into separate files so they can be loaded again
	 */
	public boolean saveKeys(String prefix) {
		fh = new FileHelper();
		fh.writeBytes("rsa."+prefix+".e.key", e.toString().getBytes());
		fh.writeBytes("rsa."+prefix+".d.key", d.toString().getBytes());
		fh.writeBytes("rsa."+prefix+".n.key", n.toString().getBytes());
		return true;
	}
	
	/**
	 * @param prefix
	 * @return
	 * Loads the keys from the files specified by prefix
	 */
	public boolean loadKeys(String prefix) {
		fh = new FileHelper();
		e = new BigInteger(fh.readLine("rsa."+prefix+".e.key"));
		d = new BigInteger(fh.readLine("rsa."+prefix+".d.key"));
		n = new BigInteger(fh.readLine("rsa."+prefix+".n.key"));
		//System.out.println("n: " + n);
		//System.out.println("e: " + e);
		//System.out.println("d: " + d);
		return true;
	}
	
	/**
	 * @param msg
	 * @return
	 * Encrypts the message specified by msg into a ciphertext
	 */
	public String encrypt(String msg) {
		BigInteger m = new BigInteger(msg.getBytes());
		if (m.compareTo(n) != -1) {
			lib.error("Message is too long; split into smaler chunks");
		}
		
		BigInteger c = m.modPow(e, n);
		return c.toString();
	}

	/**
	 * @param cipher
	 * @return
	 * Decrypts the ciphertext specifeid by cipher into cleartext
	 */
	public String decrypt(String cipher) {
		BigInteger c = new BigInteger(cipher);
		if (c.compareTo(n) != -1) {
			lib.error("Message is too long; split into smaler chunks");
		}
		
		BigInteger m = c.modPow(d, n);
		return new String(m.toByteArray());
	}
	
}
