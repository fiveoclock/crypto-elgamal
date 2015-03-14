package crypto;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertHelper {
	private LibCrypto lib = new LibCrypto();
	
	public String getCertInfo(Certificate cert) {
		X509Certificate x = (X509Certificate) cert;
		
		String ret = "Version: \t"+x.getVersion()
				+ "\nSerial Number: \t"+x.getSerialNumber().toString(16)
				+ "\nSubject: \t"+x.getSubjectDN()
				+ "\nIssuer: \t"+x.getIssuerDN()
				+ "\nValid from/to: \t"+x.getNotBefore()+" to "+x.getNotAfter()
				+ "\nSignatur name: \t"+x.getSigAlgName().toString()
				+ "\nSignatur: \t"+new BigInteger(x.getSignature())
				+ "\nPublic Key: \t"+x.getPublicKey()+"\n";
	    return ret;
	}
	
	public boolean verifyCert(Certificate ca, Certificate cert) {
		if (ca == null || cert == null) {
			lib.error("One of the certificates is null.");
			return false;
		}
		try {
			cert.verify(ca.getPublicKey());
		} 
		catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
			lib.error("Error when trying to verify the certificate: "+e.getMessage(), e);
			return false;
		} 
		return true;
	}
	
	public Certificate readCert(String filename) {
		Certificate cert = null;
		try {
			FileHelper fh = new FileHelper();
			BufferedInputStream bis = fh.openFile(filename);
			
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
	
			while (bis.available() > 0) {
				cert = cf.generateCertificate(bis);
			}
		}
		catch (IOException e) {
			lib.error("Error reading the certificate: "+filename+" - exiting", e);
		} catch (CertificateException e) {
			lib.error("Error when trying to interpret the certificate: "+filename, e);
		}
		return cert;
	}

}
