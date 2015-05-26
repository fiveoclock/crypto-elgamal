package crypto;

import java.io.Serializable;

public class SignedMessage implements Serializable {
	private static final long serialVersionUID = -1298872165113L;
	private Signature signature;
	private byte[] msg;
	
	SignedMessage () {}
	
	SignedMessage (byte[] msg) {
		this.msg = msg;
	}
	
	SignedMessage (byte[] msg, Signature signature) {
		this(msg);
		this.signature = signature;
	}
	
	public Signature getSignature() {
		return signature;
	}
	public void setSignature(Signature signature) {
		this.signature = signature;
	}
	
	public byte[] getMsg() {
		return msg;
	}
	public void setMsg(byte[] msg) {
		this.msg = msg;
	}
}
