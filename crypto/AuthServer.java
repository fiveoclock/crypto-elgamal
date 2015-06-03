package crypto;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.*;
import java.util.Arrays;
import java.util.Random;

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
	        boolean fail = false;

	        // generate and send stage 1 authentication message
	        BigInteger rand = new BigInteger(64, new Random());
	        String hostname = InetAddress.getLocalHost().getHostName();
	        String challenge = System.currentTimeMillis() + "." + rand + "@" + hostname;
	        byte[] array = challenge.getBytes("UTF-8");
	        String d = new String(array);
	        System.out.println("Generated challenge: " + d);
	        
	        AuthMsg stage1 = new AuthMsg(array);
	        outStream.writeObject(stage1);
			
	        // receive stage 2 authentication message
	        AuthMsg stage2 = (AuthMsg) inStream.readObject();
	        // sanity checks
	        if (stage2.getStage() != AuthMsg.RESPONSE) {
	        	System.out.println("Incorrect auth state received");
	        	fail = true;
	        }
	        if (stage2.getChallenge() == null || stage2.getUsername() == null) {
	        	System.out.println("Malformed message");
	        	fail = true;
	        }
	        if ( !Arrays.equals(stage2.getChallenge().getMsg(), array) ) {
	        	System.out.println("Modified challenge received" + new String());
	        	fail = true;
	        }
	        // safety measures
	        if ( stage2.getUsername().matches("[^a-zA-Z0-9_\\-\\.]")) {
	        	System.out.println("Illegal username received" + stage2.getUsername() );
	        	fail = true;
	        }
	        
	        // if everything is good until here - start auth
	        if ( fail == false) {	
		        // authentication checks
		        String user = stage2.getUsername();
		        Elgamal elgamal = new Elgamal();
		        elgamal.loadPublicKey(user);
		        
		        if (elgamal.verify(stage2.getChallenge())) {
		        	System.out.println("User " + user + " was authenticated");
		        	stage2.setStage(AuthMsg.AUTHENTICATED);
		        }
		        else {
		        	System.out.println("User " + user + " was not authenticated - signature verification failed");
		        	stage2.setStage(AuthMsg.AUTH_FAILED);
		        }
	        }
	        // Failure
	        else {
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