package crypto;

import java.io.*;
import java.net.*;

/**
 * @author alex
 * This class combines various methods that are needed for both servers and clients
 */
public class NetHelper extends Thread {
	private LibCrypto lib = new LibCrypto();
	private ServerSocket serverSocket;
	private Socket clientSocket;
	private String service;
	private String keys;
	
	private PrintWriter out;
	private InputStreamReader insr;
	private BufferedReader inbr;

	public NetHelper() { }
	
	/**
	 * @param socket
	 * @param service
	 * Constructor; for threaded use
	 */
	public NetHelper(Socket sock, String service) {
		this(sock, service, null);
	}
	
	/**
	 * @param socket
	 * @param service
	 * @param keys
	 * Constructor; for threaded use
	 */
	public NetHelper(Socket sock, String service, String keys) {
		this.clientSocket = sock;
		this.service = service;
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
	private boolean setupHandles(Socket sock) {
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

	public void run() {
		String input;

		// Hashing Service
		if (service == "hash") {
			send("Welcome to the crypto service.\r"
					+ " Every line you send will be hashed with SHA-1 and sent back.\n"
					+ " Be careful tough as everything is transmitted unencrypted, thus secret services will most likely capture this.\n");

			while ((input = receiveLine()) != null) {
				if (!input.equals("")) {
					String hash = lib.getHexHash("SHA-1", input.getBytes());
					System.out.println(input + " / SHA-1: " + hash);
					send(hash + "\n");
				}
			}
		}
		// Elgamal Service
		if (service == "elgamal") {
			Elgamal elgamal = new Elgamal(keys);
			send("Welcome to the Elgamal signing and verification service.\r"
					+ " To sign a line enter 'sign <input>'; to verify a message enter the 'verify <r> <s> <input>' - h4v3 phun\n");

			
			//elgamal.sign(input.getBytes());
			
			
			while ((input = receiveLine()) != null) {
				if (!input.equals("")) {
					String hash = lib.getHexHash("SHA-1", input.getBytes());
					System.out.println(input + " / SHA-1: " + hash);
					send(hash + "\n");
				}
			}
		}
		

		System.out.println("Client disconnected; IP: " + getClientIP());
		close();
	}
}
