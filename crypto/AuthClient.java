package crypto;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.*;

/**
 * @author alex
 * 
 */
public class AuthClient {
	private Socket socket;
	private ObjectInputStream inStream;
	private ObjectOutputStream outStream;
	private String username;
	
	Elgamal elgamal;
	private LibCrypto lib;

	/**
	 * @param socket
	 * Constructor
	 */
	public AuthClient(String username) {
		this.username = username;
        // initialize Elgamal engine and load user keys
        elgamal = new Elgamal(username);
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
			socket = new Socket(host,port);
			outStream = new ObjectOutputStream(socket.getOutputStream());
	        inStream = new ObjectInputStream(socket.getInputStream());
	        return true;
		} catch (IOException e) {
			lib.printError(e);
			return false;
		}
    }

	public boolean authenticate() {
        try {
        	// receive stage 1 auth message
	        AuthMsg stage1 = (AuthMsg) inStream.readObject();
	        System.out.println("Received challenge - " + new String(stage1.getChallenge().getMsg()) );

	        // sign the challenge
	        Signature s = elgamal.sign(stage1.getChallenge().getMsg());
	        // generate a signed message from the challenge
	        SignedMessage response = new SignedMessage(stage1.getChallenge().getMsg(), s);
	        System.out.println("Signed the challenge");
	        
	        // create a new AuthMsg
	        AuthMsg stage2 = new AuthMsg(username, response);
	        
	        // send response to server
	        outStream.writeObject(stage2);
	        
	        // wait for reply
	        AuthMsg reply = (AuthMsg) inStream.readObject();
	        if (reply.getStage() == AuthMsg.AUTHENTICATED) {
	        	System.out.println("Authenticated successfully to the server");
	        	return true;
	        }
	        else {
	        	System.out.println("Authentication unsuccessful");
	        	return false;
	        }
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
        catch (ClassNotFoundException e) {
        	System.out.println("Internal error; class not found");
        	return false;
		}
	}
}