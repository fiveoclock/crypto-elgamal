package crypto;

import java.io.Serializable;
import java.math.BigInteger;

public class Signature implements Serializable {
	private static final long serialVersionUID = 298372771663127L;
	private BigInteger r, s;
	
	public Signature() { }
	
	public Signature(BigInteger r, BigInteger s) {
		this.r = r;
		this.s = s;
	}
	
	public Signature(String r, String s) {
		this.r = new BigInteger(r);
		this.s = new BigInteger(s);
	}

	public BigInteger getR() {
		return r;
	}

	public void setR(BigInteger r) {
		this.r = r;
	}

	public BigInteger getS() {
		return s;
	}

	public void setS(BigInteger s) {
		this.s = s;
	}
}
