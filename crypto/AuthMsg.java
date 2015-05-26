package crypto;

import java.io.Serializable;

public class AuthMsg implements Serializable {

	private static final long serialVersionUID = 1L;
	
	private int stage;
	private SignedMessage challenge;
	private String username;
	
	public static final int START = 0;
	public static final int CHALLENGE = 1;
	public static final int RESPONSE = 2;
	public static final int AUTH_FAILED = 5;
	public static final int AUTHENTICATED = 6;
	
	public AuthMsg() {
		this.stage = START;
	}
	
	public AuthMsg(String challenge) {
		this.stage = CHALLENGE;
		this.challenge = new SignedMessage(challenge.getBytes());
	}
	
	public AuthMsg(String username, SignedMessage response) {
		this.stage = RESPONSE;
		this.username = username;
		this.challenge = response;
	}
	
	public int getStage() {
		return stage;
	}
	public void setStage(int state) {
		this.stage = state;
	}
	
	public SignedMessage getChallenge() {
		return challenge;
	}
	public void setChallenge(SignedMessage challenge) {
		this.challenge = challenge;
	}
	
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
}
