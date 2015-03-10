package crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class DSA {
	private static BigInteger zero = BigInteger.ZERO;
	private static BigInteger one = BigInteger.ONE;
	private LibCrypto lib;
	private FileHelper fh;
	
	private BigInteger p, q, g;
	private BigInteger x, y;
	
	public DSA() {
		lib = new LibCrypto();
	}
	
	public void generateSignature() {
		q = lib.generatePrime(160);
		System.out.println("q: " + q);
		System.out.print("Calculating p ");
		/*
	    int pLength;
	    do {
	    	pLength = 512 + 64*lib.randInt(2);
	        p = lib.generatePrime(pLength);
	        BigInteger pTemp = p.subtract(BigInteger.ONE);
	        p = p.subtract(pTemp.remainder(q));
	        System.out.print(".");
	    } 
	    while (!p.isProbablePrime(30) || p.bitLength() != pLength);
	    */
	    p = generateP(q, 512);
	    System.out.println("\np: " + p);
	    System.out.println("Rest: " + p.subtract(one).mod(q));
		
	    //////////// calculate g
	    // g = h^((p–1)/q) mod p
	    // Choose g, a number whose multiplicative order modulo p is q. 
	    // This may be done by setting g = h(p–1)/q mod p for some arbitrary h (1 < h < p−1), 
	    // and trying again with a different h if the result comes out as 1. Most choices of h will 
	    // lead to a usable g; commonly h=2 is used.
	    
	    g = BigInteger.valueOf(2).modPow(p.subtract(one).divide(q), p);
	    System.out.println("g: "+g);
	    
	    ////////// generate x
	    do {
	    	x = new BigInteger(q.bitCount(), new Random());
        } 
	    while (x.compareTo(zero) == -1 || x.compareTo(g) == 1);
	    
	    
	    ////////// calculate y
	    y = g.modPow(x, p);
	    
	    System.out.println("Private key (x): " + x);
        System.out.println("Public key (y): " + y);

	}
	
	private BigInteger generateP(BigInteger q, int l) {
	    if (l % 64 != 0) {
	        throw new IllegalArgumentException("L value is wrong");
	    }
	    int primeCenterie = 20;
	    Random rand = new Random();
	    BigInteger pTemp;
	    BigInteger pTemp2;
	    do {
	        pTemp = new BigInteger(l, primeCenterie, rand);
	        pTemp2 = pTemp.subtract(BigInteger.ONE);
	        pTemp = pTemp.subtract(pTemp2.remainder(q));
	        System.out.print(".");
	    } while (!pTemp.isProbablePrime(primeCenterie) || pTemp.bitLength() != l);
	    return pTemp;
	}

	
	public boolean saveKeys(String prefix) {
		fh = new FileHelper();
		fh.writeBytes("dsa."+prefix+".p.key", p.toString().getBytes());
		fh.writeBytes("dsa."+prefix+".q.key", q.toString().getBytes());
		fh.writeBytes("dsa."+prefix+".g.key", g.toString().getBytes());
		fh.writeBytes("dsa."+prefix+".x.key", x.toString().getBytes());
		fh.writeBytes("dsa."+prefix+".y.key", y.toString().getBytes());
		return true;
	}
	
	public boolean loadKeys(String prefix) {
		fh = new FileHelper();
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
	
	public String sign2(String message) {
	    ////////// generate k
		BigInteger k;
	    do {
	    	k = new BigInteger(q.bitCount(), new Random());
        } 
	    while (x.compareTo(zero) == -1 || x.compareTo(g) == 1);
	    System.out.println("k: "+k);
	    
	    //////////generate r
		BigInteger r = g.modPow(k, p).mod(q);
		//todo: if r == 0 calc k again
		System.out.println("r: "+r);
		
		//////////generate s
		// todo use internal hash function
		BigInteger s;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.update(message.getBytes());
	        BigInteger hash = new BigInteger(md.digest());
	        s = (k.modInverse(q).multiply(hash.add(x.multiply(r)))).mod(q);
		}
		catch (NoSuchAlgorithmException ex) {
	        System.out.println("error");
	        s = one;
	    }
		// todo check if s = 0 calc k again
		       		
        System.out.println("s: "+s);
        return null;
	}
	
	public BigInteger sign(String message) {
		byte[] data = message.getBytes();
	    ////////// generate k
		BigInteger k;
	    do {
	    	k = new BigInteger(q.bitCount(), new Random());
        } 
	    while (k.compareTo(zero) == -1 || k.compareTo(g) == 1);
	    System.out.println("k: "+k);
	    
	    //////////generate r
		BigInteger r = g.modPow(k, p).mod(q);
		//todo: if r == 0 calc k again
		System.out.println("r: "+r);
	    
	    
	    ///
	    MessageDigest md;
	    BigInteger s = BigInteger.ONE;
	    try {
	        md = MessageDigest.getInstance("SHA-1");
	        md.update(data);
	        BigInteger hash = new BigInteger(md.digest());
	        s = (k.modInverse(q).multiply(hash.add(x.multiply(r)))).mod(q);
	    } catch (NoSuchAlgorithmException ex) {
	    	System.out.println("error");
	    }
	    System.out.println("s: "+s);
	    return s;
	}

	public boolean verify(String r2, String s2, String message) {
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
	        md.update(message.getBytes());
	        BigInteger hash = new BigInteger(md.digest());
	        BigInteger w = s.modInverse(q);
	        BigInteger u1 = hash.multiply(w).mod(q);
	        BigInteger u2 = r.multiply(w).mod(q);
	        v = ((g.modPow(u1, p).multiply(y.modPow(u2, p))).mod(p)).mod(q);
	    } 
	    catch (NoSuchAlgorithmException ex) {
	    	System.out.println("error");
	    }
	    return v.compareTo(r) == 0;
	}
}
