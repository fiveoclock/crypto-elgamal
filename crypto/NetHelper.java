package crypto;

import java.io.*;
import java.net.*;

public class NetHelper {
	private ServerSocket serverSocket;
	private Socket clientSocket;
	
	private PrintWriter out;
	private BufferedReader in;

	public boolean listen(int port) {
		try {
			serverSocket = new ServerSocket(port);
		    clientSocket = serverSocket.accept();
		    
		    out = new PrintWriter(clientSocket.getOutputStream(), true);
		    in = new BufferedReader( new InputStreamReader(clientSocket.getInputStream()));
		} 
		catch (IOException e) {
			System.out.println(e.getMessage());
			return false;
		}
		return true;
	}
	
}
