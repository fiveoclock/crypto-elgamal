package crypto;

import java.math.BigInteger;

public class Crypto {
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
			case "client":			c.checkArgs(5);	c.netClient(args[2], args[3], args[4]); break;
			default: 				printUsage("Unknown command in network");
			} break;
		case "elgamal": 		c.checkArgs(2); switch(args[1]) {
			case "generate-keys": 	c.checkArgs(3); c.elgamalGenerateKeys(args[2]); break;
			case "encrypt":			c.checkArgs(4);	c.elgamalEncrypt(args[2], args[3]); break;
			case "decrypt": 		c.checkArgs(5); c.elgamalDecrypt(args[2], args[3], args[4]); break;
			case "sign": 			c.checkArgs(4); c.elgamalSign(args[2], args[3]); break;
			case "verify": 			c.checkArgs(5);	c.elgamalVerify(args[2], args[3], args[4], args[5]); break;
			case "auth-server":		c.checkArgs(3); c.elgamalAuthServer(args[2]); break;
			case "auth-client":		c.checkArgs(4);	c.elgamalAuthClient(args[2], args[3]); break;
			case "service": 		c.checkArgs(4);	c.netStartElgamalService(args[2], args[3]); break;
			default: 				printUsage("Unknown command in elgamal");
			} break;
		default: 					printUsage("Please specify command");
		}
	}
	
	// Hashing
	private void hash(String func, String text) {
		LibCrypto lib = new LibCrypto();
		System.out.println(lib.getHexHash(func, text.getBytes()));
	}

	// Elgamal
	private void elgamalGenerateKeys(String prefix) {
		Elgamal elgamal = new Elgamal();
		elgamal.generateKeys(2048);
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
	private void elgamalAuthServer(String port) {
		NetHelper net = new NetHelper();
		if (net.listen(Integer.parseInt(port)) ) {
			System.out.println("Listening on port: " + port);
			
			while (true) {
				AuthServer serverThread = new AuthServer(net.acceptConnection() );
				serverThread.start();
				System.out.println("Client connected; IP: " + net.getClientIP());
			}
		}
	}
	
	private void elgamalAuthClient(String host, String port) {
		NetHelper net = new NetHelper();
		if (net.connect(host, Integer.parseInt(port)) ) {
			System.out.println("Connected to " + host + ":" + port);
			
			long start_time, end_time;
			long time1, time2;

			String rec;
			do {
				rec = net.receiveLine();
			}
			while ( !rec.equals("") );
			
			// Signing
			System.out.println("Sending signing request for message: ");
			net.send("sign\n");
			start_time = System.nanoTime();
			
			String r = ""; 
			String s = "";
			do {
				rec = net.receiveLine();
				if (rec.startsWith(" r: ")) {
					r = rec.substring(4);
				}
				if (rec.startsWith(" s: ")) {
					s = rec.substring(4);
				}
			}
			while ( !rec.equals("") );
			end_time = System.nanoTime();
			time1 = (end_time - start_time)/1000/1000;
			System.out.println("Received signature\n");
			
			// Verficication
			System.out.println("Sending verification request");
			net.send("verify\n");
			net.send(r+"\n");
			net.send(s+"\n");
			start_time = System.nanoTime();
			
			rec = net.receiveLine();
			if (rec.endsWith(" > Signature is correct!")) {
				System.out.println(" > correct");
			}
			else if (rec.endsWith(" > Signature is incorrect!")) {
				System.out.println(" > not correct!");
			}
			else {
				System.out.println("ERROR: " + rec);
			}
			end_time = System.nanoTime();
			time2 = (end_time - start_time)/1000/1000;
			
			net.send("exit\n");
			System.out.println("\nRequired time in ms: \nSigning: " + time1 + "\nVerifying: " + time2);
		}
	}
	
	private void netStartElgamalService(String prefix, String port) {
		NetHelper net = new NetHelper();
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
		NetHelper net = new NetHelper();
		if (net.listen(Integer.parseInt(port)) ) {
			System.out.println("Listening on port: " + port);
			
			while (true) {
				NetHelper serverThread = new NetHelper(net.acceptConnection(), "hash");
				serverThread.start();
				System.out.println("Client connected; IP: " + net.getClientIP());
			}
		}
	}
	private void netClient(String host, String port, String message) {
		NetHelper net = new NetHelper();
		if (net.connect(host, Integer.parseInt(port)) ) {
			System.out.println("Connected to " + host + ":" + port);
			
			// remove newline and carriage return characters from message
			message = message.replace("\n", "").replace("\r", "");
			
			long start_time, end_time;
			long time1, time2;

			String rec;
			do {
				rec = net.receiveLine();
			}
			while ( !rec.equals("") );
			
			// Signing
			System.out.println("Sending signing request for message: \"" + message + "\"");
			net.send("sign\n");
			net.send(message + "\n");
			start_time = System.nanoTime();
			
			String r = ""; 
			String s = "";
			do {
				rec = net.receiveLine();
				if (rec.startsWith(" r: ")) {
					r = rec.substring(4);
				}
				if (rec.startsWith(" s: ")) {
					s = rec.substring(4);
				}
			}
			while ( !rec.equals("") );
			end_time = System.nanoTime();
			time1 = (end_time - start_time)/1000/1000;
			System.out.println("Received signature\n");
			
			// Verficication
			System.out.println("Sending verification request");
			net.send("verify\n");
			net.send(message + "\n");
			net.send(r+"\n");
			net.send(s+"\n");
			start_time = System.nanoTime();
			
			rec = net.receiveLine();
			if (rec.endsWith(" > Signature is correct!")) {
				System.out.println(" > correct");
			}
			else if (rec.endsWith(" > Signature is incorrect!")) {
				System.out.println(" > not correct!");
			}
			else {
				System.out.println("ERROR: " + rec);
			}
			end_time = System.nanoTime();
			time2 = (end_time - start_time)/1000/1000;
			
			net.send("exit\n");
			System.out.println("\nRequired time in ms: \nSigning: " + time1 + "\nVerifying: " + time2);
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
