package crypto;

import java.io.*;
import java.net.*;

/**
 * @author alex
 * This class combines various methods that are needed for both servers and clients
 */
public class NetHelper {
	private LibCrypto lib = new LibCrypto();
	private ServerSocket serverSocket;
	private Socket clientSocket;
	
	private PrintWriter out;
	private InputStreamReader insr;
	private BufferedReader inbr;

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
	public boolean acceptConnection() {
		try {
		    clientSocket = serverSocket.accept();
		    setupHandles(clientSocket);
		    return true;
		} 
		catch (IOException e) {
			lib.printError(e);
			return false;
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
}
