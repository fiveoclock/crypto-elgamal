package crypto;

import java.io.*;
import java.net.*;

public class Telnet extends Thread {
	private LibCrypto lib = new LibCrypto();
	private ServerSocket serverSocket;
	private Socket clientSocket;
	private String keys;
	
	private PrintWriter out;
	private InputStreamReader insr;
	private BufferedReader inbr;

	public Telnet() { }
	
	/**
	 * @param socket
	 * Constructor; for threaded use
	 */
	public Telnet(Socket sock) {
		this(sock,  null);
	}
	
	/**
	 * @param socket
	 * @param keys
	 * Constructor; for threaded use
	 */
	public Telnet(Socket sock, String keys) {
		this.clientSocket = sock;
		this.keys = keys;
		setupHandles(clientSocket);
	}

	/**
	 * @param port
	 * @return
	 * Opens the specified port
	 */
	public boolean listen(int port) {
		try {
			serverSocket = new ServerSocket(port);
		    return true;
		} 
		catch (IOException e) {
			lib.printError(e);
			return false;
		}
	}
	
	/**
	 * @return
	 * Waits for incoming connections
	 */
	public Socket acceptConnection() {
		try {
		    clientSocket = serverSocket.accept();
		    setupHandles(clientSocket);
		    return clientSocket;
		} 
		catch (IOException e) {
			lib.printError(e);
			return clientSocket;
		}
	}
	
	/**
	 * @param host
	 * @param port
	 * @return
	 * Client method to connect to the specified destination
	 */
	public boolean connect(String host, int port) {
        System.out.println("Attempting to connect to "+host+":"+port);
        try {
			clientSocket = new Socket(host,port);
	        setupHandles(clientSocket);
	        return true;
		} catch (IOException e) {
			lib.printError(e);
			return false;
		}
    }
	
	/**
	 * @param sock
	 * @return
	 * Creates readers and writers from the given socket 
	 */
	public boolean setupHandles(Socket sock) {
		try {
			out = new PrintWriter(sock.getOutputStream(), true);
			insr = new InputStreamReader(sock.getInputStream());
			inbr = new BufferedReader( insr);
			return true;
		} catch (IOException e) {
			lib.printError(e);
			return false;
		}
	}
    
	/**
	 * @param msg
	 * Sends the given string
	 */
	public void send(String msg) {
		out.print(msg);
		out.flush();
	}
	
	/**
	 * @return
	 * Retrieves one line
	 */
	public String receiveLine() {
        try {
			return inbr.readLine(); 
		} catch (IOException e) {
			lib.printError(e);
			return null;
		}
    }
	
    /**
     * @return
     * Receives all available data
     */
    public String receive() {
    	String s = "";
		try {
			while (inbr.ready()) 
				s += receiveLine()+"\n";
		} catch (IOException e) {
			lib.printError(e);
		}
		return s;
    }
	
	/**
	 * Closes the socket
	 */
	public void close() {
		try {
			inbr.close();
			out.close();
		} catch (IOException e) {
			lib.printError(e);
		}
	}
	
	/**
	 * @return
	 * returns the client IP as string
	 */
	public String getClientIP() {
		return clientSocket.getInetAddress().getHostAddress().toString();
	}
	
	public void signClient(String host, String port, String message) {
		if (connect(host, Integer.parseInt(port)) ) {
			System.out.println("Connected to " + host + ":" + port);
			
			// remove newline and carriage return characters from message
			message = message.replace("\n", "").replace("\r", "");
			long start_time, end_time;
			long time1, time2;

			String rec;
			do {
				rec = receiveLine();
			}
			while ( !rec.equals("") );
			
			// Signing
			System.out.println("Sending signing request for message: \"" + message + "\"");
			send("sign\n");
			send(message + "\n");
			start_time = System.nanoTime();
			
			String r = ""; 
			String s = "";
			do {
				rec = receiveLine();
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
			send("verify\n");
			send(message + "\n");
			send(r+"\n");
			send(s+"\n");
			start_time = System.nanoTime();
			
			rec = receiveLine();
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
			
			send("exit\n");
			System.out.println("\nRequired time in ms: \nSigning: " + time1 + "\nVerifying: " + time2);
		}
	}
	
	
	public String askForInput(String msg) {
		String input;
		while (true) {
			send(msg);
			input = receiveLine();
			if (input != null & !input.equals(""))
				return input;
		}
	}

	public void run() {
		String output = "";

		Elgamal elgamal = new Elgamal(keys);
		String msg = "";
		String help = "The following commands are available: sign, verify, help, exit";
		
		send("Welcome to the Elgamal signing and verification service.\n  " + help + "\n\n");
		while (true) {
			String command = askForInput("# "); 
			if (command.startsWith("sign")) {
				msg = askForInput("message: ");
				Signature signature = elgamal.sign(msg.getBytes());
				output = "Signature \n r: " + signature.getR() + "\n s: " + signature.getS() +"\n";
				send(output + "\n");
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
				send(output + "\n\n");
			}
			if (command.startsWith("help")) {
				send(help + "\n\n");
			}
			if (command.startsWith("exit") | command.startsWith("quit")) {
				send("Bye!\n");
				return;
			}
			System.out.println(getClientIP() + " " + command + " " + msg);
		}
	}
}