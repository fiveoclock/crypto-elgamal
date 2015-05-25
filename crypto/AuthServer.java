package crypto;

import java.io.*;
import java.net.*;

/**
 * @author alex
 * This class combines various methods that are needed for both servers and clients
 */
public class AuthServer extends Thread {
	private LibCrypto lib = new LibCrypto();
	private NetHelper net = new NetHelper();
	private ServerSocket serverSocket;
	private Socket clientSocket;
	private String keys;
	
	private PrintWriter out;
	private InputStreamReader insr;
	private BufferedReader inbr;

	public AuthServer() { }
	
	/**
	 * @param socket
	 * Constructor; for threaded use
	 */
	public AuthServer(Socket sock) {
		this(sock, null);
	}
	
	/**
	 * @param socket
	 * @param keys
	 * Constructor; for threaded use
	 */
	public AuthServer(Socket sock, String keys) {
		this.clientSocket = sock;
		this.keys = keys;
		net.setupHandles(clientSocket);
	}
	
	
	public String askForInput(String msg) {
		String input;
		while (true) {
			net.send(msg);
			input = net.receiveLine();
			if (input != null & !input.equals(""))
				return input;
		}
	}

	public void run() {
		String input, output = "";
		// Elgamal Service
		Elgamal elgamal = new Elgamal(keys);
		String msg = "";
		
		while (true) {
			String command = askForInput("# "); 
			if (command.startsWith("sign")) {
				msg = askForInput("message: ");
				Signature signature = elgamal.sign(msg.getBytes());
				output = "Signature \n r: " + signature.getR() + "\n s: " + signature.getS() +"\n";
				net.send(output + "\n");
			}
			if (command.startsWith("verify")) {
				String r, s;
				msg = askForInput("message: ");
				r = askForInput("r: ");
				s = askForInput("s: ");

				SignedMessage sm = new SignedMessage(msg.getBytes(), new Signature(r, s));
				if (elgamal.verify(sm)) {
					output = " > Signature is correct!";
				}
				else {
					output = " > Signature is incorrect!";
				}
				net.send(output + "\n\n");
			}
			if (command.startsWith("help")) {
				net.send(help + "\n\n");
			}
			if (command.startsWith("exit") | command.startsWith("quit")) {
				net.send("Bye!\n");
				return;
			}
			System.out.println(net.getClientIP() + " " + command + " " + msg);
		}
	}
}