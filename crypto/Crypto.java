package crypto;

import java.math.BigInteger;

public class Crypto {
	private LibCrypto lib = new LibCrypto();
	private NetHelper net = new NetHelper();
	private static int argsNum;

    public Crypto() { }

	public static void main(String[] args) {
		Crypto c = new Crypto();
		argsNum = args.length;
		c.checkArgs(1);
		
		switch(args[0]) {
		case "hash": 			c.checkArgs(3); c.hash(args[1], args[2]); break;
		case "network":			c.checkArgs(2); switch(args[1]) {
			case "server":			c.checkArgs(3);	c.netServer(args[2]); break;
			case "client":			c.checkArgs(4);	c.netClient(args[2], args[3]); break;
			default: 				printUsage("Unknown command in network");
			} break;
		case "elgamal": 		c.checkArgs(2); switch(args[1]) {
			case "generate-keys": 	c.checkArgs(3); c.elgamalGenerateKeys(args[2]); break;
			case "encrypt":			c.checkArgs(4);	c.elgamalEncrypt(args[2], args[3]); break;
			case "decrypt": 		c.checkArgs(5); c.elgamalDecrypt(args[2], args[3], args[4]); break;
			case "sign": 			c.checkArgs(4); c.elgamalSign(args[2], args[3]); break;
			case "verify": 			c.checkArgs(5);	c.elgamalVerify(args[2], args[3], args[4], args[5]); break;
			case "service": 		c.checkArgs(4);	c.netStartElgamalService(args[2], args[3]); break;
			default: 				printUsage("Unknown command in elgamal");
			} break;
		default: 					printUsage("Please specify command");
		}
	}
	
	// Hashing
	private void hash(String func, String text) {
		System.out.println(lib.getHexHash(func, text.getBytes()));
	}

	// Elgamal
	private void elgamalGenerateKeys(String prefix) {
		Elgamal elgamal = new Elgamal();
		elgamal.generateKeys(1024);
		elgamal.saveKeys(prefix);
	}
	private void elgamalSign(String prefix, String message) {
		Elgamal elgamal = new Elgamal(prefix);
		Signature signature = elgamal.sign(message.getBytes());
		System.out.println("Signature \n r: " + signature.getR() + "\n s: " + signature.getS());
	}
	private void elgamalVerify(String prefix, String r, String s, String message) {
		Elgamal elgamal = new Elgamal(prefix);
		SignedMessage sm = new SignedMessage(message.getBytes(), new Signature(r, s));
		
		if (elgamal.verify(sm)) {
			System.out.println("> Correct!");
		}
		else {
			System.out.println("> Incorrect!");
		}
	}
	private void netStartElgamalService(String prefix, String port) {
		if (net.listen(Integer.parseInt(port)) ) {
			System.out.println("Listening on port: " + port);
			
			while (true) {
				NetHelper serverThread = new NetHelper(net.acceptConnection(), "elgamal", prefix);
				serverThread.start();
				System.out.println("Client connected; IP: " + net.getClientIP());
			}
		}
	}
	private void elgamalEncrypt(String prefix, String message) {
		Elgamal elgamal = new Elgamal(prefix);
		String c = elgamal.encrypt(new BigInteger(message.getBytes()));
		System.out.println("Ciphertext (B, C): " + c);
		//System.out.println("\nTesting decryption (m'): " + elgamal.decrypt(c));
	}
	private void elgamalDecrypt(String prefix, String b, String c) {
		Elgamal elgamal = new Elgamal(prefix);
		BigInteger B, C;
		B = new BigInteger(b);
		C = new BigInteger(c);
		
		String m = elgamal.decrypt(B, C);
		System.out.println("Decrypted message (m'): " + m);
	}	
	
	
	// Networking
	private void netServer(String port) {
		if (net.listen(Integer.parseInt(port)) ) {
			System.out.println("Listening on port: " + port);
			
			while (true) {
				NetHelper serverThread = new NetHelper(net.acceptConnection(), "hash");
				serverThread.start();
				System.out.println("Client connected; IP: " + net.getClientIP());
			}
		}
	}
	private void netClient(String host, String port) {
		if (net.connect(host, Integer.parseInt(port)) ) {
			System.out.println("Connected to " + host + ":" + port);

			// must often be called multiple times because it doesn't return 
			// the welcome message the first time (race-condition); alternative
			// lib.sleep(100);  // give the server some time to prepare the welcome message :/
			
			String rec;
			do {
				rec = net.receiveLine();
				System.out.println(rec);
			}
			while ( !rec.equals("") );
			
			net.send("sign\n");
			net.send("hallo\n");
			
			do {
				rec = net.receiveLine();
				System.out.println(rec);
			}
			while ( !rec.equals("") );
		}
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
		.append("  network:                                                  \n")
		.append("     server [port]                                          \n")
		.append("       - starts a network hashing service; hashes incoming hashes and sends them back \n")
		.append("     client [address] [port]                                \n")
		.append("       - client for the hashing service                     \n")
		.append("                                                            \n")
        .toString();
		System.out.println(usage);
	}
}
