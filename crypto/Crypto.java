package crypto;

public class Crypto {
	private LibCrypto lib;
	private RSA rsa;
	private DSA dsa;
	private CertHelper certH;
	private NetHelper net;

    public Crypto() {
		lib = new LibCrypto();
		rsa = new RSA();
		dsa = new DSA();
		certH = new CertHelper();
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
		
		int aNum = args.length;
		if (aNum > 0) {
			switch(args[0]) {
			case "hash":
				if (aNum > 2)
					c.hash(args[1], args[2]);
				else
					printUsage("Not enough parameters");
				break;
			case "ecc":
				if (aNum > 2)
					c.eccTest(args[1], args[2]);
				else
					printUsage("Not enough parameters");
				break;
			case "cert":
				if (aNum > 1) {
					switch(args[1]) {
					case "read":
						if (aNum > 2)
							c.certRead(args[2]);
						else
							printUsage("Not enough parameters");
						break;
					case "verify":
						if (aNum > 3)
							c.verifyCert(args[2], args[3]);
						else
							printUsage("Not enough parameters");
						break;
					}
					break;
				}
			case "network":
				if (aNum > 1) {
					switch(args[1]) {
					case "server":
						if (aNum > 2)
							c.startServer(args[2]);
						else
							printUsage("Not enough parameters");
						break;
					case "client":
						if (aNum > 3)
							c.startClient(args[2], args[3]);
						else
							printUsage("Not enough parameters");
						break;
					}
					break;
				}
			case "rsa":
				if (aNum > 1) {
					switch(args[1]) {
					case "generate-keys":
						if (aNum > 2)
							c.rsaGenerateKeys(args[2]);
						else
							printUsage("Not enough parameters");
						break;
					case "encrypt":
						if (aNum > 3)
							c.rsaEncrypt(args[2], args[3]);
						else
							printUsage("Not enough parameters");
						break;
					case "decrypt":
						if (aNum > 3)
							c.rsaDecrypt(args[2], args[3]);
						else
							printUsage("Not enough parameters");
						break;
					default:
						printUsage("Unknown command");
						}
					break;
				}
			case "dsa":
				if (aNum > 1) {
					switch(args[1]) {
					case "generate-keys":
						if (aNum > 2)
							c.dsaGenerateKeys(args[2]);
						else
							printUsage("Not enough parameters");
						break;
					case "sign":
						if (aNum > 3)
							c.dsaSign(args[2], args[3]);
						else
							printUsage("Not enough parameters");
						break;
					case "verify":
						if (aNum > 5)
							c.dsaVerify(args[2], args[3], args[4], args[5]);
						else
							printUsage("Not enough parameters");
						break;
					default:
						printUsage("Unknown command");
						}
					break;
				}
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
	
	private void eccTest(String a, String b) {
		ECC ecc = new ECC(lib.getBI(-9), lib.getBI(12), lib.getBI(13));
		ecc.test();
	}
	
	private void certRead(String filename) {
		System.out.println( certH.getCertInfo((certH.readCert(filename))));
	}
	private void verifyCert(String file_ca, String file_cert) {
		if ( certH.verifyCert(certH.readCert(file_ca), certH.readCert(file_cert)) ) {
			System.out.println(certH.getCertInfo(certH.readCert(file_cert)));
			System.out.println("The certificate "+file_cert+" was issued by the CA "+file_ca);
		}
		else {
			System.out.println("The certificate "+file_cert+" was NOT issed by the CA "+file_ca);
		}
	}
	
	/// Networking
	private void startServer(String port) {
		net = new NetHelper();
		net.listen(Integer.parseInt(port));
	}
	
	private void startClient(String filename, String filenam) {
		System.out.println( certH.getCertInfo((certH.readCert(filename))));
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
	private void dsaGenerateKeys(String prefix) {
		dsa.generateKeys();
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
