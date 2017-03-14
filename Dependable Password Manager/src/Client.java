import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;

import javax.crypto.*;

public class Client {

	DataOutputStream out;
	Key pubKey;
	Key privKey;
	Socket clientSocket = null;
	
	public Client(String username, String password) {

		KeyStore ks;
		
		try {
			//Specify keystore type in the future
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
			init(ks, username, password);
		} catch (KeyStoreException e) {
			System.out.println("KeyStoreException");
		}
		
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
		System.out.println("Ready");
	}

	public static void main(String[] args) throws IOException {
		
		String username = System.console().readLine();
		String password = System.console().readLine();


		Client client = new Client(username, password);

        while(true) {
	        String command = System.console().readLine();
	        System.out.println(command);
	        switch (command) {
	        
				case "register":
				client.Testregister();
					break;
					
				case "put":
				client.Testput();
					break;
					
				case "get":
				client.Testget();
					break;

				default:
					break;
			}
        }
	}


	public void Testregister() throws IOException{
		String TestpubKey = "banana";
		out.flush();
		out.writeBytes("register: " + TestpubKey + '\n');
		//out.writeBytes(TestpubKey);
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

	public void init(KeyStore ks, String username, String password) {
		
		java.io.FileInputStream fis = null;
	    try {
	        fis = new java.io.FileInputStream(username + "KeyStore");
	        //gets keystore if it already exists
	        ks.load(fis, password.toCharArray());
	        System.out.println("KeyStore loaded");
	    } catch (NoSuchAlgorithmException | CertificateException e) {
	    	e.printStackTrace();
		} 
	    catch (IOException e) {
	    	//I think this exception indicates that the keystore doesn't exist for the given password
	    	//load keystore with null passsword -> empty keystore
	    	System.out.println("Create new keystore");
	    	createNewKeyStore(ks, fis, username, password);
	    }
	    
	    /*finally {
	        if (fis != null) {
	            fis.close();
	        }
	    }*/
	    
		/*ks.getKey(username, password.toCharArray());
		ks.setEntry(username, null, null);*/

	}
	
	public void createNewKeyStore(KeyStore ks, java.io.FileInputStream fis,
			String username, String password) {
		/*KeyStore.ProtectionParameter protParam =
		        new KeyStore.PasswordProtection(password.toCharArray());*/
		
		try {
			ks.load(fis, null);
			
			// store away the keystore
		    java.io.FileOutputStream fos = null;
		    
		    //give key store same name as user?
		    fos = new java.io.FileOutputStream(username + "KeyStore");
		    ks.store(fos, password.toCharArray());
		    System.out.println("Created new KeyStore");
		} catch (NoSuchAlgorithmException | KeyStoreException |
				CertificateException | IOException e) {
			e.printStackTrace();
		}
	}
	
	public void register(Key publicKey){
		
	}
	
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password){
			
	}
	
	public void get(Key publicKey, byte[] domain, byte[] username, byte[] password){
		
	}
	
}
