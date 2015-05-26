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

	/**
	 * @param socket
	 * Constructor
	 */
	public AuthClient(Socket sock, String username) {
		this.socket = sock;
		this.username = username;
	}

	public boolean authenticate() {
        try {
			outStream = new ObjectOutputStream(socket.getOutputStream());
	        inStream = new ObjectInputStream(socket.getInputStream());

	        // receive stage 1 auth message
	        AuthMsg stage1 = (AuthMsg) inStream.readObject();
	        System.out.println("Received challenge");
	        
	        // initialize Elgamal engine
	        Elgamal elgamal = new Elgamal();
	        elgamal.loadKeys(username);

	        // sign the challenge
	        Signature s = elgamal.sign(stage1.getChallenge().getMsg());
	        // generate a signed message from the challenge
	        SignedMessage response = new SignedMessage(stage1.getChallenge().getMsg(), s);
	        System.out.println("Signed the challenge");
	        
	        // create a new AuthMsg
	        AuthMsg stage2 = new AuthMsg(username, response);
	        
	        // send response to server
	        outStream.writeObject(stage1);
	        
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