package crypto;

import java.io.*;
import java.net.*;

public class NetHelper {
	private LibCrypto lib = new LibCrypto();
	private ServerSocket serverSocket;
	private Socket clientSocket;
	
	private PrintWriter out;
	private BufferedReader in;

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
	
	private boolean setupHandles(Socket sock) {
		try {
			out = new PrintWriter(sock.getOutputStream(), true);
			in = new BufferedReader( new InputStreamReader(sock.getInputStream()));
			return true;
		} catch (IOException e) {
			lib.printError(e);
			return false;
		}
	}
    
	public void send(String msg) {
		out.print(msg);
		out.flush();
	}
	
	public String receiveLine() {
        try {
			return in.readLine(); 
		} catch (IOException e) {
			lib.printError(e);
			return null;
		}
    }
	
    public String receive() {
    	String s = null;
		try {
			while (in.ready()) {
				s += in.readLine();
			}
		} catch (IOException e) {
			lib.printError(e);
		}
		return s;
    }
	
	public void close() {
		try {
			in.close();
			out.close();
		} catch (IOException e) {
			lib.printError(e);
		}
	}
	
	public String getClientIP() {
		return clientSocket.getInetAddress().getHostAddress().toString();
	}
}
