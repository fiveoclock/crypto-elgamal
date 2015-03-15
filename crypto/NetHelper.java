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
		    clientSocket = serverSocket.accept();
		    setupHandles(clientSocket);
		    return true;
		} 
		catch (IOException e) {
			System.out.println(e.getMessage());
			return false;
		}
	}
	
	public boolean connect(String host, int port) throws UnknownHostException, IOException{
        System.out.println("Attempting to connect to "+host+":"+port);
        clientSocket = new Socket(host,port);
        setupHandles(clientSocket);
        return true;
    }
	
	public boolean setupHandles(Socket sock) {
		try {
			out = new PrintWriter(sock.getOutputStream(), true);
			in = new BufferedReader( new InputStreamReader(sock.getInputStream()));
			return true;
		} catch (IOException e) {
			lib.printError(e);
			return false;
		}
	}

    public void send1() {
        try {
        	BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(this.clientSocket.getOutputStream()));
			writer.write("Hello. You are connected to a Simple Socket Server. What is your name?");
	        writer.flush();
		} catch (IOException e) {
			lib.printError(e);
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
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
    }
	
    public String receive() {
    	String s;
		while ((s = receiveLine()) != null) {
		    System.out.println(s);
		}
		return s;
    }
	
	public void start(int port) throws IOException {
        System.out.println("Starting the socket server at port:" + port);
        serverSocket = new ServerSocket(port);
        
        //Listen for clients. Block till one connects
        
        System.out.println("Waiting for clients...");
        Socket client = serverSocket.accept();
        
        //A client has connected to this server. Send welcome message
        //sendWelcomeMessage(client);
    }
	
	public String getClientIP() {
		return clientSocket.getInetAddress().getHostAddress().toString();
	}
    



	
}
