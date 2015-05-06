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
    	rnd = new Random(System.currentTimeMillis() + System.nanoTime());
    }

    /**
     * @param func
     * @param data
     * @return
     * Hashes the given string using the hash function specified by func and returns the hash as byte array;
     * See Java documentation for the selection of available hash functions
     */
    public byte[] hash(String func, byte[] data) {
    	byte[] hash = null;
    	MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance(func);
			messageDigest.update(data);
	    	hash = messageDigest.digest();
		} catch (NoSuchAlgorithmException e) {
			System.out.println(func + " is not a valid hash function");
		}
		return hash;
    }

    /**
     * @param func
     * @param data
     * @return
     * Hashes a message and returns it as hexadecimal hash string
     */
    public String getHexHash(String func, byte[] data) {
    	byte[] hash = hash(func, data);
    	return (new HexBinaryAdapter()).marshal(hash).toLowerCase();
    }
    
    /**
     * @return
     * Returns an instance of Random(); centralized for eventually better randomness
     */
    public Random getRandom() {
    	return rnd;
    }
    
    /**
     * @param maxSize
     * @return
     * Returns a random positive int of the desired maximum size
     */
    public int randInt(int maxSize) {
    	return (int) (Math.random() * maxSize); 
    }
    
    /**
     * @param maxSize
     * @return
     * Returns a random int that can be negative of the desired maximum size
     */
    public int randNegInt(int maxSize) {
    	return randInt(maxSize) - maxSize/2;
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
    public void printError(String msg, Exception e) {
		System.out.println(msg + " - " + e.getMessage());;
	}
    /**
     * @param e
     * Prints the exception message to console and then exits
     */
    public void printError(Exception e) {
		System.out.println("Error"+" - "+e.getMessage());
	}
	/**
	 * @param msg
	 * Prints a message specified by msg to console and then exits
	 */
	public void printError(String msg) {
		System.out.println("Error: " + msg);
	}
    
    /**
     * @param msg
     * @param e
     * Prints a message specified by msg and the exception message to console and then exits 
     */
    public void exit(String msg, Exception e) {
    	printError(msg, e);
		System.exit(1);
	}
    /**
     * @param e
     * Prints the exception message to console and then exits
     */
    public void exit(Exception e) {
    	printError(e);
		System.exit(1);
	}
	/**
	 * @param msg
	 * Prints a message specified by msg to console and then exits
	 */
	public void exit(String msg) {
		printError(msg);
		System.exit(1);
	}
	
	/**
	 * @param milliseconds
	 * Just puts the thread to sleep for the defined amount of time
	 */
	public void sleep(int milliseconds) {
		try {
		    Thread.sleep(milliseconds);
		} catch(InterruptedException ex) {
		    Thread.currentThread().interrupt();
		}
	}
}
