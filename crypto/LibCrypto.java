package crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

/**
 * @author alex
 * Provides some functions that can be used by the other classes
 */
public class LibCrypto {
	public static BigInteger zero = BigInteger.ZERO;
	public static BigInteger one = BigInteger.ONE;
	public static BigInteger two = BigInteger.valueOf(2);
	public static BigInteger three = BigInteger.valueOf(3);

    private Random rnd;

    public LibCrypto() {
    	rnd = new Random(System.currentTimeMillis());
    }

    /**
     * @param func
     * @param s
     * @return
     * Hashes the given string using the hash function specified by func and returns the hash as byte array;
     * See Java documentation for the selection of available hash functions
     */
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
    
    /**
     * @param func
     * @param s
     * @return
     * Hashes a message and returns it as hexadecimal hash string
     */
    public String getHexHash(String func, String s) {
    	byte[] hash = hash(func, s);
    	return (new HexBinaryAdapter()).marshal(hash);
    }
    
    /**
     * @return
     * Returns an instance of Random(); centralized for better randomness
     */
    public Random getRandom() {
    	return rnd;
    }
    
    /**
     * @param length
     * @return
     * Returns a random positive int of the desired length
     */
    public int randInt(int length) {
    	return (int) (Math.random() * length);
    }
    
    /**
     * @param length
     * @return
     * Returns a random int that can be negative of the desired length
     */
    public int randNegInt(int length) {
    	return randInt(length) - length/2;
    }
    
    /**
     * @param length
     * @return
     * Returns a prime with the desired length as BitInteger 
     */
    public BigInteger generatePrime(int length) {
        BigInteger prime = BigInteger.probablePrime(length, rnd);
        return prime;
    }
    
    /**
     * @param msg
     * @param e
     * Prints a message specified by msg and the exception message to console and then exits 
     */
    public void error(String msg, Exception e) {
		System.out.println(msg + " - " + e.getMessage());
		System.exit(1);
	}
    /**
     * @param e
     * Prints the exception message to console and then exits
     */
    public void error(Exception e) {
		System.out.println("Error"+" - "+e.getMessage());
		System.exit(1);
	}
	/**
	 * @param msg
	 * Prints a message specified by msg to console and then exits
	 */
	public void error(String msg) {
		System.out.println("Error: " + msg);
		System.exit(1);
	}
}
