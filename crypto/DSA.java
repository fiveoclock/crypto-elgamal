package crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author alex
 * Provides DSA key generation and handling, signing and verfification
 */
public class DSA {
	private static BigInteger zero = BigInteger.ZERO;
	private static BigInteger one = BigInteger.ONE;
	private static int primeCertainty = 20;

	private LibCrypto lib;
	private FileHelper fh;
	
	private BigInteger p, q, g;
	private BigInteger x, y;
	
	public DSA() {
		lib = new LibCrypto();
		fh = new FileHelper();
	}
	
	/**
	 * Generates the DSA keys in order to be able to sign and verify messages later
	 */
	public void generateKeys() {
		// p and q Length pairs: (1024,160), (2048,224), (2048,256), and (3072,256).
		// q must be a prime; choosing 160 Bit for q
		System.out.print("Calculating q: ");
		q = lib.generatePrime(160);
		System.out.println(q + " - Bitlength: " + q.bitLength());
		
		// p must be a prime
		System.out.print("Calculating p ");
		p = calculateP(q);
	    System.out.println("\np: " + p + " - Bitlength: " + p.bitLength());
	    System.out.println("Test-Division: ((p-1)/q) - Rest: " + p.subtract(one).mod(q));
	    
	    // choose an h with (1 < h < p−1) and try again if g comes out as 1.
    	// Most choices of h will lead to a usable g; commonly h=2 is used.
	    System.out.print("Calculating g: ");
	    BigInteger h = BigInteger.valueOf(2);
	    BigInteger pMinusOne = p.subtract(one);
	    do {
	    	g = h.modPow(pMinusOne.divide(q), p);
	    	System.out.print(".");
	    }
	    while (g == one);
	    System.out.println(" "+g);
	    
	    // Choose x by some random method, where 0 < x < q
	    // this is going to be the private key
	    do {
	    	x = new BigInteger(q.bitCount(), lib.getRandom());
        }
	    while (x.compareTo(zero) == -1);
	    
	    // Calculate y = g^x mod p
	    y = g.modPow(x, p);
	    
        System.out.println("y: " + y);
        System.out.println("-------------------");
        System.out.println("Private key (x): " + x);
	}
	
	/**
	 * @param q
	 * @return
	 * Helper function that calculates a p that fits to q;
	 *   p must be a prime of the length (L): 512 < L < 1024 where L must be a multiple of 64;
	 *   also q must be a divider of (p-1);
	 *   A lot of loops are needed until p is found
	 */
	private BigInteger calculateP(BigInteger q) {
		// p must be a prime of the length (L): 512 < L < 1024 where L must be a multiple of 64
		// also q must be a divider of (p-1)
		int pLength = 512 + 64*lib.randInt(8);
	    BigInteger pTest;
	    BigInteger pMinusOne;
	    
	    do {
	        pTest = new BigInteger(pLength, primeCertainty, lib.getRandom());
	        pMinusOne = pTest.subtract(one);
	        pTest = pTest.subtract(pMinusOne.remainder(q));
	        System.out.print(".");
	    }
	    while (!pTest.isProbablePrime(primeCertainty) || pTest.bitLength() != pLength);
	    return pTest;
	}

	/**
	 * @param prefix
	 * @return
	 * Saves the keys for later use
	 */
	public boolean saveKeys(String prefix) {
		fh.writeBytes("dsa."+prefix+".p.key", p.toString().getBytes());
		fh.writeBytes("dsa."+prefix+".q.key", q.toString().getBytes());
		fh.writeBytes("dsa."+prefix+".g.key", g.toString().getBytes());
		fh.writeBytes("dsa."+prefix+".x.key", x.toString().getBytes());
		fh.writeBytes("dsa."+prefix+".y.key", y.toString().getBytes());
		return true;
	}
	
	/**
	 * @param prefix
	 * @return
	 * Loads the previously saved keys
	 */
	public boolean loadKeys(String prefix) {
		p = new BigInteger(fh.readLine("dsa."+prefix+".p.key"));
		q = new BigInteger(fh.readLine("dsa."+prefix+".q.key"));
		g = new BigInteger(fh.readLine("dsa."+prefix+".g.key"));
		x = new BigInteger(fh.readLine("dsa."+prefix+".x.key"));
		y = new BigInteger(fh.readLine("dsa."+prefix+".y.key"));
		System.out.println("p: " + p);
		System.out.println("q: " + q);
		System.out.println("g: " + g);
		System.out.println("x: " + x);
		System.out.println("y: " + y);
		System.out.println("--------------------------");
		return true;
	}
	
	/**
	 * @param msg
	 * Creates the signature (r,s) of the message specified by msg
	 */
	public void sign(String msg) {
		byte[] data = msg.getBytes();
		BigInteger k, r, s;
		
		do {
			do {
			    // Generate a random per-message value k where 0 < k < q
			    do {
			    	k = new BigInteger(q.bitCount(), lib.getRandom());
		        }
			    while (k.compareTo(zero) == 0);
			    System.out.println("k: "+k);
			    
			    // Calculate r = (g^k mod p) mod q
			    // in the unlikely case that r=0, start again with a different random k
				r = g.modPow(k, p).mod(q);
			}
			while (r.compareTo(zero) == 0);
			System.out.println("r: "+r);
			
			// Calculate s = k^-1 (H(m) + xr) mod q
		    MessageDigest md;
		    try {
		        md = MessageDigest.getInstance("SHA-1");
		        md.update(data);
		        BigInteger hash = new BigInteger(md.digest());
		        s = (k.modInverse(q).multiply(hash.add(x.multiply(r)))).mod(q);
		    } catch (NoSuchAlgorithmException e) {
				lib.exit(e);
				s = zero;
		    }
		}
		while (s.compareTo(zero) == 0);
	    System.out.println("s: "+s);
	}

	/**
	 * @param r
	 * @param s
	 * @param msg
	 * @return
	 * Verifies if the signature (r, s) fits to the message specified by msg
	 */
	public boolean verify(String r2, String s2, String msg) {
		BigInteger r = new BigInteger(r2);
		BigInteger s = new BigInteger(s2);
		
		if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(q) >= 0) {
	        return false;
	    }
	    if (s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(q) >= 0) {
	        return false;
	    }
	    MessageDigest md;
	    BigInteger v = BigInteger.ZERO;
	    try {
	        md = MessageDigest.getInstance("SHA-1");
	        md.update(msg.getBytes());
	        BigInteger hash = new BigInteger(md.digest());
	        BigInteger w = s.modInverse(q);
	        BigInteger u1 = hash.multiply(w).mod(q);
	        BigInteger u2 = r.multiply(w).mod(q);
	        v = ((g.modPow(u1, p).multiply(y.modPow(u2, p))).mod(p)).mod(q);
	    } 
	    catch (NoSuchAlgorithmException e) {
			lib.exit(e);
	    }
	    return v.compareTo(r) == 0;
	}
}
