package crypto;

import java.math.BigInteger;

/**
 * @author alex
 * Provides Elgamal key generation and handling, encryption and decryption
 * 
 * todo:
	network code
	split loading of keys - public and private
	adapt bitlenght
	document
	split into separate project
	read about which hash function to use
	authentication / zero knowledge ???
	 
 */
public class Elgamal {
	private static BigInteger zero = BigInteger.ZERO;
	private static BigInteger one = BigInteger.ONE;
	private static BigInteger two = BigInteger.valueOf(2);
	private static int primeCertainty = 20;

	private LibCrypto lib;
	private FileHelper fh;
	
	private BigInteger p, g, A;
	private BigInteger a;
	private BigInteger pMinusOne;
	
	public Elgamal() {
		lib = new LibCrypto();
		fh = new FileHelper();
	}
	
	/**
	 * @param prefix
	 * @return
	 * Creates an instance of the class and loads the specified keys
	 */
	public Elgamal(String prefix) {
		this();
		loadKeys(prefix);
	}	
	
	/**
	 * Generates the keys
	 */
	public void generateKeys(int length) {
		System.out.print("Calculating domain parameters p and q ");
		BigInteger q;
		do {
			p = BigInteger.probablePrime(length, lib.getRandom());
			pMinusOne = p.subtract(one);
			q = pMinusOne.divide(two);
			System.out.print(".");
		}
		while (!q.isProbablePrime(primeCertainty));
		System.out.println("\np: " + p);
		System.out.println("q: " + q);
		
		// Find a Generator for the group 
		BigInteger gTest;
		System.out.print("\nSearching for a generator ");
		do {
			g = new BigInteger(length-lib.randInt(length/2), lib.getRandom());
			
			// Calculate a generator - Algorithm 4.86
			// if the term   g ^ ((p-1)/q)
			// is not 1 then it is a generator.
			// From the previous calculation we know that (p-1)/q = 2
			gTest = g.modPow(q, p);
			System.out.print(".");
		}
		while (gTest.equals(one) || g.equals(zero));
		System.out.println("\ng: " + g);
		
		// Generate a
		System.out.print("\nGenerating a ");
		do {
			a = new BigInteger(length-lib.randInt(length/8), lib.getRandom());
			System.out.print(".");
		}
		while ( a.compareTo(one) == -1 || a.compareTo(p.subtract(two)) == 1 );
		System.out.println("\na: " + a);
		
		// Calculate g^a mod p (A)
		A = g.modPow(a, p);
		System.out.println("\nA: " + A);
		
		// Print keys
		System.out.println("Private key: ");
		System.out.println("a: " + a);
		System.out.println("\nPublic key: ");
		System.out.println("p: " + p);
		System.out.println("g: " + g);
		System.out.println("A: " + A);
	}
	
	
	/**
	 * Debug method to check if the provided number is a generator of p.
	 * Ofcourse this is only feasable with small groups
	 */
	private void testGenerator(BigInteger g) {
		BigInteger i = zero;
		while (i.compareTo(pMinusOne) == -1) {
			BigInteger calc = g.modPow(i, p);
			//System.out.println(i + ": " + calc);
			if (calc.equals(one) && !i.equals(zero))
				break;
			i = i.add(one);
		}
		System.out.println("Elements found: " + i +" of " + pMinusOne);
	}
	
	/**
	 * Debug method to test randomness
	 */
	private void testRandomness() {
		BigInteger k;
		while (true) {
		k = new BigInteger(p.bitLength(), lib.getRandom());
		System.out.println(k);
		}
	}
	

	/**
	 * @param prefix
	 * @return
	 * Saves the keys for later use
	 */
	public boolean saveKeys(String prefix) {
		String pub = p + "/" + g + "/" + A;
		fh.writeBytes("elgamal."+prefix+".pub", pub.getBytes());
		fh.writeBytes("elgamal."+prefix+".priv", a.toString().getBytes());
		return true;
	}
	
	/**
	 * @param prefix
	 * @return
	 * Loads the previously saved keys
	 */
	public boolean loadKeys(String prefix) {
		a = new BigInteger(fh.readLine("elgamal."+prefix+".priv"));
		
		String pub = fh.readLine("elgamal."+prefix+".pub");
		String[] pubkeys = pub.split("/");
		p = new BigInteger(pubkeys[0]);
		g = new BigInteger(pubkeys[1]);
		A = new BigInteger(pubkeys[2]);
		// calculate p-1
		pMinusOne = p.subtract(one);
		
		// Print keys
		System.out.println("Private key: ");
		System.out.println("a: " + a);
		System.out.println("\nPublic key: ");
		System.out.println("p: " + p);
		System.out.println("g: " + g);
		System.out.println("A: " + A);
		System.out.println("--------------------------");
		return true;
	}
	
	/**
	 * @param m
	 * @return
	 * Encrypts the given message to ciphertext
	 */
	public String encrypt(BigInteger m) {
		if (m.compareTo(p.subtract(one)) != -1) {
			lib.exit("Message is too long; split into smaler chunks");
		}
		
		BigInteger k, B, C;
		// select a random k
		do {
			k = new BigInteger(p.bitLength(), lib.getRandom());
		}
		while ( k.compareTo(one) == -1 || k.compareTo(p.subtract(two)) == 1 );
		
		// Calculate B
		B = g.modPow(k, p);
		C = m.multiply(A.modPow(k, p).mod(p));
		
		return B + ", " + C;
	}

	/**
	 * @param cipher
	 * @return
	 * Decrypts the ciphertext specifeid by cipher into cleartext
	 */
	public String decrypt(BigInteger B, BigInteger C) {
		BigInteger x, m;
		x = p.subtract(one).subtract(a);
		m = B.modPow(x, p).multiply(C).mod(p);
		return new String(m.toByteArray());
	}
	
	
	/**
	 * @param data
	 * Creates the signature (r,s) of the message specified by data
	 */
	public Signature sign(byte[] data) {
		BigInteger k, kInverse, r, hash, s;
		
		do {
		    // Generate a random per-message value k
			// where 0 < k < q; and gcd(k,pMinusOne) = 1
			do {
				k = new BigInteger(p.bitLength(), lib.getRandom());
			}
			while ( k.compareTo(one) == -1 || k.compareTo(p.subtract(two)) == 1 || !(k.gcd(pMinusOne).equals(one)) );

		    // pre-calculate the inverse ok k
		    kInverse = k.modInverse(pMinusOne);

		    // Calculate r = g^k mod p
			r = g.modPow(k, p);

			// Calculate s = (H(m) - a*r) * k^-1 mod (p-1)
			hash = new BigInteger(lib.hash("SHA-1", data));
			s = hash.subtract(a.multiply(r)).multiply(kInverse).mod(pMinusOne);
		}
		while (s.compareTo(zero) == 0);
	    return new Signature(r, s);
	}

	/**
	 * @param SignedMessage
	 * @return
	 * Verifies if the supplied SignedMessage can be verified
	 */
	public boolean verify(SignedMessage sm) {
		BigInteger r = sm.getSignature().getR();
		BigInteger s = sm.getSignature().getS();
		BigInteger hash, v1, v2;
		
		if (r.compareTo(one) == -1 || r.compareTo(pMinusOne) == 1) {
	        return false;
	    }
	    if (s.compareTo(one) == -1 || s.compareTo(pMinusOne) == 1) {
	        return false;
	    }
	    
	    // v1 = g^(h(m))
	    hash = new BigInteger(lib.hash("SHA-1", sm.getMsg()));
	    v1 = g.modPow(hash, p);
	    // v2 = y^r * r^s mod p
	    v2 = A.modPow(r, p).multiply(r.modPow(s, p)).mod(p);
	    
	    // Accept the signature if and only if v1 = v2
	    return v1.equals(v2);
	}
}
