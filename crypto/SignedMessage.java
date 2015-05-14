package crypto;

public class SignedMessage {
	private Signature signature;
	private byte[] msg;
	
	SignedMessage () {}
	
	SignedMessage (byte[] msg, Signature signature) {
		this.msg = msg;
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
