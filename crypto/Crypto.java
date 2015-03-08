package crypto;

public class Crypto {
	private LibCrypto lib;
	private RSA rsa;
	private DSA dsa;

    private int id = 0;
    
	public Crypto() {
		lib = new LibCrypto();
		rsa = new RSA();
		dsa = new DSA();
	}

	public static void main(String[] args) {
		// make an instance
		Crypto c = new Crypto();
		
		for(String arg:args) {
			switch(arg) {
				case "hello":
					System.out.println("hello switch string");
					break;
				case "-verbose":
					System.out.println("verbose mode activated");
					break;
		      }
	    }
		
		if (args.length > 0) {
			switch(args[0]) {
			case "hash":
				if (args.length > 2)
					c.hash(args[1], args[2]);
				else
					printUsage("Not enough parameters");
				break;
			case "rsa":
				switch(args[1]) {
				case "generate-keys":
					if (args.length > 2)
						c.rsaGenerateKeys(args[2]);
					else
						printUsage("Not enough parameters");
					break;
				case "encrypt":
					if (args.length > 3)
						c.rsaEncrypt(args[2], args[3]);
					else
						printUsage("Not enough parameters");
					break;
				case "decrypt":
					if (args.length > 3)
						c.rsaDecrypt(args[2], args[3]);
					else
						printUsage("Not enough parameters");
					break;
				default:
					printUsage("Unknown command");
					}
				break;
			case "dsa":
				switch(args[1]) {
				case "generate-signature":
					if (args.length > 2)
						c.dsaGenerateSignature(args[2]);
					else
						printUsage("Not enough parameters");
					break;
				case "sign":
					if (args.length > 3)
						c.dsaSign(args[2], args[3]);
					else
						printUsage("Not enough parameters");
					break;
				case "verify":
					if (args.length > 5)
						c.dsaVerify(args[2], args[3], args[4], args[5]);
					else
						printUsage("Not enough parameters");
					break;
				default:
					printUsage("Unknown command");
					}
				break;
			default:
				printUsage("Unknown command");
			}
		}
		else {
			printUsage();
		}
	}
	
	private void hash(String func, String text) {
		System.out.println(lib.getHexHash(func, text));
	}
	
	// RSA//
	private void rsaGenerateKeys(String prefix) {
		rsa.generateKeys(2048);
		rsa.saveKeys(prefix);
	}
	private void rsaEncrypt(String prefix, String message) {
		rsa.loadKeys(prefix);
		rsa.encrypt(message);
	}
	private void rsaDecrypt(String prefix, String cipher) {
		rsa.loadKeys(prefix);
		rsa.decrypt(cipher);
	}

	// DSA//
	private void dsaGenerateSignature(String prefix) {
		dsa.generateSignature();
		dsa.saveKeys(prefix);
	}
	private void dsaSign(String prefix, String message) {
		dsa.loadKeys(prefix);
		dsa.sign(message);
	}
	private void dsaVerify(String prefix, String r, String s, String message) {
		dsa.loadKeys(prefix);
		if (dsa.verify(r, s, message)) {
			System.out.println("> Correct!");
		}
		else {
			System.out.println("> Incorrect!");
		}
	}
	

	// general methods
	private static void printUsage(String message) {
		printUsage();
		System.out.println(message);
	}
	private static void printUsage() {
		String help = "Usage:\n"
				+ "hash function input\n"
	    		+ " - function can be MD5, SHA-1, SHA-256\n"
	    		+ "\n"
	    		+ "rsa generate-keys key-prefix\n"
	    		+ "- generates rsa keys and saves them in files named prefix.*.key\n"
	    		+ "\n"
	    		+ "rsa encrypt key-prefix input\n"
	    		+ "- encrypts the given input using the keys specified by key-prefix\n"
	    		+ "\n"
	    		+ "rsa decrypt key-prefix input\n"
	    		+ "- decrypts the given input using the keys specified by key-prefix\n";
		System.out.println("Error: " + help);
	}
}
