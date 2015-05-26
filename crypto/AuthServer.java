package crypto;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.*;
import java.util.Random;

/**
 * @author alex
 * 
 */
public class AuthServer extends Thread {
	private Socket socket;
	private ObjectInputStream inStream;
	private ObjectOutputStream outStream;

	public AuthServer() { }
	
	/**
	 * @param socket
	 * Constructor; for threaded use
	 */
	public AuthServer(Socket sock) {
		this.socket = sock;
	}

	public void run() {
        try {
			outStream = new ObjectOutputStream(socket.getOutputStream());
	        inStream = new ObjectInputStream(socket.getInputStream());
	        
	        // generate and send stage 1 authentication message
	        BigInteger rand = new BigInteger(64, new Random());
	        String hostname = InetAddress.getLocalHost().getHostName();
	        String challenge = System.currentTimeMillis() + "." + rand + "@" + hostname;
	        System.out.println("Generated challenge: " + challenge);
	        
	        AuthMsg stage1 = new AuthMsg(challenge);
	        outStream.writeObject(stage1);
			
	        // receive stage 2 authentication message
	        AuthMsg stage2 = (AuthMsg) inStream.readObject();
	        // sanity checks
	        if (stage2.getStage() != AuthMsg.RESPONSE) {
	        	System.out.println("Incorrect auth state received");
	        	return;
	        }
	        if (stage2.getChallenge() == null || stage2.getUsername() == null) {
	        	System.out.println("Malformed message");
	        	return;
	        }
	        if ( !stage2.getChallenge().getMsg().equals(challenge)) {
	        	System.out.println("Modified challenge received");
	        	return;
	        }
	        // safety measures
	        if ( !stage2.getUsername().matches("[^a-zA-Z0-9_\\-\\.]")) {
	        	System.out.println("Illegal username received");
	        	return;
	        }
	        
	        // authentication checks
	        String user = stage2.getUsername();
	        Elgamal elgamal = new Elgamal();
	        elgamal.loadPublicKey(user);
	        
	        if (elgamal.verify(stage2.getChallenge())) {
	        	System.out.println("User " + user + " was authenticated");
	        	stage2.setStage(AuthMsg.AUTHENTICATED);
	        }
	        else {
	        	System.out.println("User " + user + " could not be authenticated");
	        	stage2.setStage(AuthMsg.AUTH_FAILED);
	        }
	        // send reply to the client
	        outStream.writeObject(stage2);
	        return;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        catch (ClassNotFoundException e) {
        	System.out.println("Internal error; class not found");
		}
	}
}