package crypto;

import java.math.BigInteger;

public class Crypto {
	private LibCrypto lib = new LibCrypto();
	private RSA rsa = new RSA();;
	private DSA dsa = new DSA();;
	private CertHelper certH = new CertHelper();
	private NetHelper net = new NetHelper();;
	private static int argsNum;

    public Crypto() { }

	public static void main(String[] args) {
		Crypto c = new Crypto();
		argsNum = args.length;
		c.checkArgs(1);
		
		switch(args[0]) {
		case "hash": 			c.checkArgs(3); c.hash(args[1], args[2]); break;
		case "ecc": 			c.checkArgs(2); switch(args[1]) {
			case "p192":			c.checkArgs(2); c.eccTest(args[1], args[2]); break;
			default: 				printUsage("Unknown command");
		} break;
		case "cert": 			c.checkArgs(2); switch(args[1]) {
			case "read": 			c.checkArgs(3); c.certRead(args[2]); break;
			case "verify": 			c.checkArgs(4); c.verifyCert(args[2], args[3]); break;
			default: 				printUsage("Unknown command");
			} break;
		case "network":			c.checkArgs(2); switch(args[1]) {
			case "server":			c.checkArgs(3);	c.startServer(args[2]); break;
			case "client":			c.checkArgs(4);	c.startClient(args[2], args[3]); break;
			default: 				printUsage("Unknown command");
			} break;
		case "rsa": 			c.checkArgs(2); switch(args[1]) {
			case "generate-keys": 	c.checkArgs(3);	c.rsaGenerateKeys(args[2]);	break;
			case "encrypt":			c.checkArgs(4);	c.rsaEncrypt(args[2], args[3]); break;
			case "decrypt": 		c.checkArgs(4); c.rsaDecrypt(args[2], args[3]); break;
			default: 				printUsage("Unknown command");
			} break;
		case "dsa": 			c.checkArgs(2); switch(args[1]) {
			case "generate-keys": 	c.checkArgs(3); c.dsaGenerateKeys(args[2]); break;
			case "sign": 			c.checkArgs(4); c.dsaSign(args[2], args[3]); break;
			case "verify": 			c.checkArgs(5);	c.dsaVerify(args[2], args[3], args[4], args[5]); break;
			default: 				printUsage("Unknown command");
			} break;
		default: 					printUsage("Unknown command");
		}
	}
	
	// Hashing
	private void hash(String func, String text) {
		System.out.println(lib.getHexHash(func, text));
	}
	
	// Certificate functions
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
	
	// RSA
	private void rsaGenerateKeys(String prefix) {
		rsa.generateKeys(2048);
		rsa.saveKeys(prefix);
	}
	private void rsaEncrypt(String prefix, String message) {
		rsa.loadKeys(prefix);
		String c = rsa.encrypt(message);
		System.out.println("Ciphertext (c): " + c);
		
		System.out.println("\nTesting decryption (m'): " + rsa.decrypt(c));
	}
	private void rsaDecrypt(String prefix, String cipher) {
		rsa.loadKeys(prefix);
		String m = rsa.decrypt(cipher);
		System.out.println("Decrypted message (m'): " + m);
	}

	// DSA
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

	// Networking
	private void startServer(String port) {
		if (net.listen(Integer.parseInt(port)) ) {
			System.out.println("Client connected - IP: " + net.getClientIP());
			net.send("Welcome to the crypto server.\n"
				+ " For every line you send you will receive the SHA-1 hash of that line. \n"
				+ " Be careful no encryption implemented so far, thus secret services will most likely capture this.\n\n");
			
			while (true) {
				String line = net.receiveLine();
				if (!line.equals("")) {
					String hash = lib.getHexHash("SHA-1", line);
					System.out.println(line + " - Hash: " + hash);
					net.send(hash + "\n");
				}
			}
		}
	}
	private void startClient(String filename, String filenam) {
		System.out.println( certH.getCertInfo((certH.readCert(filename))));
	}
	
	// ECC
	private void eccTest(String curve, String ks) {
		ECC ecc = new ECC();
		BigInteger a, b, p;
		ECPoint G = new ECPoint();
		
		if (curve.equalsIgnoreCase("p192")) {
			// set domain parameters for curve p192 as specifed by:
			// http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf
			a = BigInteger.valueOf(-3);
			b = new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16);
			p = new BigInteger("6277101735386680763835789423207666416083908700390324961279");
			ecc = new ECC(a, b, p);
			
			BigInteger Gx = new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16);
			BigInteger Gy = new BigInteger("07192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16);
			G = new ECPoint(Gx, Gy);
		}
		else {
			printUsage("Unsupported curve: " + curve);
		}
		BigInteger k = new BigInteger(ks);
		
		System.out.println("Domain parameters: \n" + ecc.toString());
		System.out.println("G: \n" + G.toString(16) );
		System.out.println("K: " + k + " (in bits: " + k.toString(2) +")\n");
		
		// Scalar multiplication
		// compare values with http://point-at-infinity.org/ecc/nisttv
		ECPoint R = ecc.scalarMultiplication(G, k);
		System.out.println(R.toString(16));
	}

	// general methods
	private void checkArgs(int required) {
		if (argsNum < required)
			printUsage("Not enough parameters provided");
	}
	private static void printUsage(String message) {
		printUsage();
		System.out.println("Error: " + message);
		System.exit(1);
	}
	private static void printUsage() {
		String usage = new StringBuilder()
        .append("Usage: crypto command [sub-command] [args]                  \n")
        .append("                                                            \n")
        .append("Command may be one of the following:                        \n")
        .append(" hash, ecc, cert, rsa, dsa, network                         \n")
        .append("                                                            \n")
        .append("Complete list of commands, sub-commands and options:        \n")
        .append("  hash:                                                     \n")
        .append("     [function] [input-text]                                \n")
        .append("       - function can any function that is supported by Java (ex. MD5, SHA-1, SHA-256)\n")
        .append("                                                            \n")
        .append("  rsa:                                                      \n")
        .append("     generate-keys [key-prefix]                             \n")
        .append("       - generates rsa keys and saves them in files named prefix.*.key\n")
        .append("     encrypt [key-prefix] [input]                           \n")
        .append("       - encrypts the given input using the keys specified by key-prefix (you must run generate-keys first)\n")
        .append("     decrypt [key-prefix] [input]                           \n")
        .append("       - decrypts the given input using the keys specified by key-prefix (you must run generate-keys first)\n")
        .append("                                                            \n")
        .append("  cert:                                                     \n")
		.append("     read [cert-file]                                       \n")
		.append("       - reads a certificate and prints some information    \n")
		.append("     verify [ca-file] [cert-file]                           \n")
		.append("       - verifies if the certificate is derived from the specified CA certificate\n")
		.append("                                                            \n")
		.append("  dsa:                                                      \n")
		.append("     generate-keys [key-prefix]                             \n")
		.append("       - generate dsa keys and save them in files named dsa.prefix.*.key\n")
		.append("     sign [key-prefix] [input]                              \n")
		.append("       - sign the input message with the keys specified by input\n")
		.append("     verify [key-prefix] [r] [s] [input]                    \n")
		.append("       - verify that the signature specified by r and s matches to the input message\n")
		.append("                                                            \n")
		.append("  network:                                                  \n")
		.append("     server [port]                                          \n")
		.append("       - start a server and listen on the spefied port      \n")
		.append("     client [address] [port]                                \n")
		.append("       - conntect to the specified address and port         \n")
		.append("                                                            \n")
		.append("  ecc:                                                      \n")
		.append("     p192 [k]                                               \n")
		.append("       - calculate point R on the NIST Curve P192           \n")
        .toString();
		System.out.println(usage);
	}
}
