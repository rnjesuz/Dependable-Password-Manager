import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.xml.bind.DatatypeConverter;

public class KeyGen {
	public static void main(String[] args) {
		
		KeyPairGenerator kpg;
		KeyPair kp = null;
		KeyStore ks = null;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			kp = kpg.genKeyPair();
			String pass = "pass";   
			ks = KeyStore.getInstance("JKS");
			
			ks.load(null, pass.toCharArray());
			    
			System.out.println("Created new KeyStore");
			    
			GenCert gen = new GenCert();
			X509Certificate[] certificate = gen.generateCertificate(kp);
			    
			ks.setKeyEntry("ServerKeys", kp.getPrivate(), pass.toCharArray(), certificate);
			    
			    
			//give key store same name as user?
			java.io.FileOutputStream fos = new java.io.FileOutputStream("ServerKeys");
			ks.store(fos, pass.toCharArray());
			        
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}