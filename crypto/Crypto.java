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
		case "elgamal": 		c.checkArgs(2); switch(args[1]) {
			case "generate-keys": 	c.checkArgs(3); c.elgamalGenerateKeys(args[2]); break;

			case "encrypt":			c.checkArgs(4);	c.elgamalEncrypt(args[2], args[3]); break;
			case "decrypt": 		c.checkArgs(5); c.elgamalDecrypt(args[2], args[3], args[4]); break;

			case "sign": 			c.checkArgs(4); c.elgamalSign(args[2], args[3]); break;
			case "verify": 			c.checkArgs(5);	c.elgamalVerify(args[2], args[3], args[4], args[5]); break;

			case "auth-server":		c.checkArgs(3); c.elgamalAuthServer(args[2]); break;
			case "auth-client":		c.checkArgs(5);	c.elgamalAuthClient(args[2], args[3], args[4]); break;

			case "sign-server":		c.checkArgs(4);	c.netStartElgamalService(args[2], args[3]); break;
			case "sign-client":		c.checkArgs(5); c.netClient(args[2], args[3], args[4]); break;

			default: 				printUsage("Unknown command in elgamal");
			} break;
		default: 					printUsage("Please specify command");
		}
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
	
	private void elgamalAuthClient(String host, String port, String username) {
		AuthClient client = new AuthClient(username);

		// measure time
		long start_time, end_time, time1;
		start_time = System.nanoTime();

		if (client.connect(host, Integer.parseInt(port)) ) {
			System.out.println("Connected to " + host + ":" + port);
			client.authenticate();
		}
		end_time = System.nanoTime();
    	time1 = (end_time - start_time)/1000/1000;
		System.out.println("\nRequired time in ms: " + time1);
	}
	
	private void netStartElgamalService(String prefix, String port) {
		NetHelper net = new NetHelper();
		if (net.listen(Integer.parseInt(port)) ) {
			System.out.println("Listening on port: " + port);
			
			while (true) {
				NetHelper serverThread = new NetHelper(net.acceptConnection(), prefix);
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
        .append("  elgamal:                                                  \n")
        .append("     generate-keys [key-prefix]                             \n")
        .append("       - generates elgamal keys and saves them in files named elgamal.[prefix].key\n")
        .append("                                                            \n")

        .append("     sign [key-prefix] [input]                              \n")
        .append("       - signs the input message with the keys specified by input \n")
        .append("     verify [key-prefix] [r] [s] [input]                    \n")
        .append("       - verifies that the signature specified by r and s matches to the input message\n")
        .append("                                                            \n")

        .append("     auth-server [port]                                     \n")
        .append("       - starts a challenge/response server for authenticating users \n")
        .append("     auth-client [host] [port] [username]                   \n")
        .append("       - starts a challenge/response client that authenticates against the server \n")
        .append("                                                            \n")

        .append("     sign-server [key-prefix] [port]                        \n")
        .append("       - starts a server that allows signing of messages and verification of signatures\n")
        .append("     sign-client [host] [port] [message]                    \n")
        .append("       - starts a client that signes the specified message and verifies the resulting signature\n")
        .append("                                                            \n")

        .append("     encrypt [key-prefix] [input]                           \n")
        .append("       - encrypts the given input using the keys specified by key-prefix\n")
        .append("     decrypt [key-prefix] [input]                           \n")
        .append("       - decrypts the given input using the keys specified by key-prefix\n")
        .toString();
		System.out.println(usage);
	}
}
