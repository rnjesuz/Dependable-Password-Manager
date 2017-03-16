import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;

public class Client {

	DataOutputStream out;
	DataInputStream in;
	int counter;
	static Key pubKey;
	static Key privKey;
	static Key serverPubKey;
	Socket clientSocket = null;
	static String username=null;
	static String password=null;
	static String serverKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCjKRQONg0//UpKjC4CPArM69ZniDJFwVe2/bHeOL+cBtMI/jTHajig5hddzSx5MzYgwZXN40KwKfXew958P/0ynh46f61e18EfXlhc23VOgnIJn26d9249MDKGwgow7bz/t7BTAU8I8oa/cjGiUcCrAh7J4rv0BajH6t6zoqGTJQIDAQAB";

	
	public Client(String username, String password) {
		
		try {
			clientSocket = new Socket("localhost", 8080);
			out = new DataOutputStream(clientSocket.getOutputStream());
			in = new DataInputStream(clientSocket.getInputStream());
		} catch (UnknownHostException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} 
		sendUsername();
		askServerClock();
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
				serverPubKey = getServerKey();
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
					String a;
					byte[] putdomain, putusername, putpassword;
					System.out.println("Insert the desired domain:");
					a = System.console().readLine();
					putdomain = hashCode(a).getBytes("UTF-8");
					System.out.println(new String(putdomain, "UTF-8"));
					System.out.println("Insert the desired username:");
					a = System.console().readLine();
					putusername = hashCode(a).getBytes("UTF-8");
					System.out.println("Insert the desired password:");
					putpassword = encrypt(System.console().readLine(), pubKey);

					client.save_password(putdomain, putusername, putpassword);
					break;
					
				case "get":
					String aa;
					byte[] getdomain, getusername;
					System.out.println("Insert the desired domain:");
					aa = System.console().readLine();
					getdomain = hashCode(aa).getBytes("UTF-8");
					System.out.println("Insert the desired username:");
					aa = System.console().readLine();
					getusername = hashCode(aa).getBytes("UTF-8");

					client.retrieve_password(getdomain, getusername);
					break;

				default:
					break;
			}
        }
	}


	public void sendUsername(){
		try {
			
			out.flush();
			out.writeInt("username".length());
			out.writeBytes("username");

			out.flush();
			out.writeInt(username.length());
			out.writeBytes(username);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void askServerClock(){
		
		try {
			out.flush();
			out.writeInt("counter".length());
			out.writeBytes("counter");
			
			counter = in.readInt();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
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

  	//HASH CODE
  	 public static String hashCode(String str) {
        int hash = 7;
		for (int i = 0; i < str.length(); i++) {
   			 hash = hash*31 + str.charAt(i);
		}
		
		System.out.println("HASH: " + "" + hash);
        return "" + hash;

    }	
	
	public void register_user(){
		 try {
			ByteBuffer bb = ByteBuffer.allocate(4);
            bb.putInt(pubKey.getEncoded().length);
           
            	
				out.flush();
				out.writeInt("register".getBytes("UTF-8").length);//Sends length of msg
				byte[] msgSign = concatenate("register".getBytes("UTF-8"), signature("register".getBytes("UTF-8")));//creates MSG+SIG
				byte[] toSend = encrypt(new String (msgSign, "UTF-8"), getServerKey());//Cipher
				out.writeInt(toSend.length);//Sends total length
				out.write(toSend);//Sends {MSG+SIG}serverpubkey
				
				out.writeInt(calculateCounter());

				out.flush();
				out.writeInt(username.length());
				out.writeBytes(username);

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
				out.writeInt("put".length());
				out.writeBytes("put");
				
				out.writeInt(calculateCounter());

				out.flush();
				out.writeInt(domain.length);
				out.write(domain);

				out.flush();
				out.writeInt(username.length);
				out.write(username);

				out.flush();
				out.writeInt(password.length);
				out.write(password);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
	}
	
	public void retrieve_password(byte[] domain, byte[] username){
		byte[] inputByte = null;
		try {
        		
				out.flush();
				out.writeInt("get".length());
				out.writeBytes("get");
				
				out.writeInt(calculateCounter());

				out.flush();
				out.writeInt(domain.length);
				out.write(domain);

				out.flush();
				out.writeInt(username.length);
				out.write(username);

				int lenght = in.readInt();
				inputByte = new byte[lenght]; 
				in.readFully(inputByte, 0, inputByte.length);

				//output = in.readLine();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		try {
			if(new String(inputByte,"UTF-8").equals("NULL")){
				System.out.println("No password stored under this domain/username");
			}
			else{System.out.println(decrypt(inputByte, privKey));}
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static Key getServerKey(){
		Key output = null;

		try {
				BufferedReader brTest = new BufferedReader(new FileReader("serverPubKey"));
	    		String text = brTest.readLine();

		    	output = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(DatatypeConverter.parseHexBinary(text)));
		    	brTest.close();
	    	
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return output;
	}
	
	public byte[] signature(byte[] array) {
		byte[] signature = null;
		Signature rsaForSign;
		try {
			rsaForSign = Signature.getInstance("SHA256withRSA");
			rsaForSign.initSign((PrivateKey) privKey);
			rsaForSign.update(array);
			signature = rsaForSign.sign();
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return signature;
	}
	

  	public boolean verigySignature(byte[] sig, byte[] data){
  		boolean verifies = false;
	  	try {
			Signature rsaForVerify = Signature.getInstance("SHA256withRSA");
			rsaForVerify.initVerify((PublicKey) getServerKey());
			rsaForVerify.update(data);
			verifies = rsaForVerify.verify(sig);
			System.out.println("Signature verifies: " + verifies);
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return verifies;
  	}
	
	public int calculateCounter(){
		counter += 42;

		System.out.println(counter);
		return counter;
	}
	
	public byte[] concatenate(byte[] a, byte[] b){
		byte c[] = null;
		
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		
		try {
			outputStream.write( a );
			outputStream.write( b );
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		c = outputStream.toByteArray( );
		
		return c;
	}
}
