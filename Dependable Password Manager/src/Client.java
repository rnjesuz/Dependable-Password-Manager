import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.*;

public class Client {

	DataOutputStream out;
	static Key pubKey;
	static Key privKey;
	Socket clientSocket = null;
	static String username=null;
	static String password=null;
	
	public Client(String username, String password) {
		
		try {
			clientSocket = new Socket("localhost", 8080);
			out = new DataOutputStream(clientSocket.getOutputStream());
		} catch (UnknownHostException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} 
		sendUsername();
		System.out.println("Ready");
	}

	public static void main(String[] args) throws IOException {
		
		
		
		while (true) {
			
			System.out.print("username: ");
			username = System.console().readLine();
			System.out.print("password: ");
			password = System.console().readLine();
			
			KeyStore ks = null;	
			
			try {
				//Specify keystore type in the future
				ks = KeyStore.getInstance("JKS");
				init(ks, username, password);
				break;
			} catch (KeyStoreException e1) {
				System.out.println("KeyStoreException");
			} catch(WrongPasswordException e2) {
				System.out.println("Wrong Password, try again");
			}
		}
		
		Client client = new Client(username, password);


        while(true) {
	        String command = System.console().readLine();
	        System.out.println(command);
	        switch (command) {
	        
				case "register":
					if(pubKey != null) {
						client.register_user();
					}
				
					break;
					
				case "put":
					byte[] domain, username, password;
					System.out.println("Insert the desired domain:");
					domain = encrypt(System.console().readLine(), pubKey);
					System.out.println("Insert the desired username:");
					username = encrypt(System.console().readLine(), pubKey);
					System.out.println("Insert the desired password:");
					password = encrypt(System.console().readLine(), pubKey);

					client.save_password(domain, username, password);
					break;
					
				case "get":
				client.Testget();
					break;

				default:
					break;
			}
        }
	}


	public void sendUsername(){
		try {
			out.flush();
			out.writeBytes("username#" + username + '\n');
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void Testput() throws IOException{
		String TestpubKey = "banana";
		String Testdomain = "url";
		String Testusername = "Cena";
		String Testpassword = "123";
		out.flush();
		out.writeBytes("put: " + TestpubKey + Testdomain + Testusername + Testpassword +'\n');
	}
	
	public void Testget() throws IOException{
		String TestpubKey = "banana";
		String Testdomain = "url";
		String Testusername = "Cena";
		String Testpassword = "123";
		
		out.writeBytes("get: ");
		out.writeBytes(TestpubKey + Testdomain + Testusername + Testpassword);
	}

	public static void init(KeyStore ks, String username, String password) throws WrongPasswordException {
		
		java.io.FileInputStream fis = null;
	    try {
	        fis = new java.io.FileInputStream(username + "KeyStore");
	        //gets keystore if it already exists
	        ks.load(fis, password.toCharArray());
	        System.out.println("KeyStore loaded");
	        
	        privKey = ks.getKey(username, password.toCharArray());
	        pubKey = ks.getCertificate(username).getPublicKey();
	        
	        System.out.println(pubKey.getAlgorithm());
			System.out.println(privKey.getAlgorithm());
	    
		} catch (IOException e) {
	    	//User has WRONG PASSWORD or USER DOESNT HAVE KEYSTORE
			//Adjust filepath if necessary
			File folder = new File (".");
			File[] listOfFiles = folder.listFiles();

		    for (int i = 0; i < listOfFiles.length; i++) {
		      if (listOfFiles[i].getName().equals(username + "KeyStore")) {
		    	  System.out.println("Wrong Password, try again");
		    	  throw new WrongPasswordException();
		      }
		    }
			
	    	createNewKeyStore(ks, fis, username, password);
	    	
	    } catch (NoSuchAlgorithmException | CertificateException
	    		| UnrecoverableKeyException | KeyStoreException e) {
	    	e.printStackTrace();
	    }
	}
	
	
	public static void createNewKeyStore(KeyStore ks, java.io.FileInputStream fis,
			String username, String password) {
		
		try {
		    
		    ks.load(null, password.toCharArray());
		    
		    System.out.println("Created new KeyStore");
		    
		    //Create keys and store in keystore
		    KeyPair kp = createKeyPair(); 		
		    
			GenCert gen = new GenCert();
		    X509Certificate[] certificate = gen.generateCertificate(kp);
		    
		    ks.setKeyEntry(username, kp.getPrivate(), password.toCharArray(), certificate);
		    
		    privKey = kp.getPrivate();
		    pubKey = ks.getCertificate(username).getPublicKey();
		    
		    //give key store same name as user?
		    java.io.FileOutputStream fos = new java.io.FileOutputStream(username + "KeyStore");
		    ks.store(fos, password.toCharArray());
		    
		} catch (NoSuchAlgorithmException | KeyStoreException |
				CertificateException | IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static KeyPair createKeyPair(){
		KeyPairGenerator kpg;
		KeyPair kp = null;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(1024);
			kp = kpg.genKeyPair();
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return kp;
	}

	//USES PUBLIC KEY
	public static byte[] encrypt(String text, Key key) {
	    byte[] cipherText = null;
	    try {
	      // get an RSA cipher object and print the provider
	      final Cipher cipher = Cipher.getInstance("RSA");
	      // encrypt the plain text using the public key
	      cipher.init(Cipher.ENCRYPT_MODE, key);
	      cipherText = cipher.doFinal(text.getBytes());
	    } catch (Exception e) {
	      e.printStackTrace();
	    }
	    return cipherText;
  	}

  	//USES PRIVATE KEY
  	public static String decrypt(byte[] text, Key key) {
	    byte[] dectyptedText = null;
	    try {
	      // get an RSA cipher object and print the provider
	      final Cipher cipher = Cipher.getInstance("RSA");

	      // decrypt the text using the private key
	      cipher.init(Cipher.DECRYPT_MODE, key);
	      dectyptedText = cipher.doFinal(text);

	    } catch (Exception ex) {
	      ex.printStackTrace();
    	}

    	return new String(dectyptedText);
  	}	
	
	public void register_user(){
		
			ByteBuffer bb = ByteBuffer.allocate(4);
            bb.putInt(pubKey.getEncoded().length);
            try {
            	out.flush();
				out.writeBytes("register#" + username + "#" + '\n');
				clientSocket.getOutputStream().write(bb.array());
				clientSocket.getOutputStream().write(pubKey.getEncoded());
				clientSocket.getOutputStream().flush();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 
	}
	
	public void save_password(byte[] domain, byte[] username, byte[] password){
			try {
				out.flush();
				out.writeBytes("put#" + domain + "#" + username + "#" + password + "#" + '\n');
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
	}
	
	public void retrieve_password(byte[] domain, byte[] username, byte[] password){
		//Should return password from server
	}
	
}
