package crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

public class LibCrypto {

    private Random rnd;

    public LibCrypto() {
    	rnd = new Random(System.currentTimeMillis());
    }

    public byte[] hash(String func, String s) {
    	byte[] hash = null;
    	MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance(func);
			messageDigest.update(s.getBytes());
	    	hash = messageDigest.digest();
		} catch (NoSuchAlgorithmException e) {
			System.out.println(func + " is not a valid hash function");
		}
		return hash;
    }
    public String getHexHash(String func, String s) {
    	byte[] hash = hash(func, s);
    	return (new HexBinaryAdapter()).marshal(hash);
    }
    
    public Random getRandom() {
    	return rnd;
    }
    
    public BigInteger generatePrime(int length) {
        BigInteger prime = BigInteger.probablePrime(length, rnd);
        return prime;
    }
    
    public int randInt(int length) {
    	return (int) (Math.random() * length);
    }
    
    public int randNegInt(int length) {
    	return randInt(length) - length/2;
    }
    
    public BigInteger getBI(String s) {
    	return new BigInteger(s.getBytes());
    }
    public BigInteger getBI(int i) {
    	return BigInteger.valueOf(i);
    }
}
