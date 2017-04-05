import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

import java.nio.ByteBuffer;

import javax.crypto.*;

public class ServerThread extends Thread {

	private Socket socket = null;
	private String clientUsername = "";
	static Key privKey;
	static Key pubKey;
	DataOutputStream out;
	int counter = 1;

	public ServerThread(Socket socket) {

		super("MiniServer");
		this.socket = socket;
		privKey = getServerKey("priv");
		pubKey = getServerKey("pub");

	}

	public void run() {
		
		while (socket.isConnected()) {
			
			try {
				out = new DataOutputStream(this.socket.getOutputStream());
				
				DataInputStream in = new DataInputStream(socket.getInputStream());
				int msgLenght = in.readInt();
				int lenght = in.readInt();
				byte[] inputByte = new byte[lenght];
				byte[] decipherInput;
				byte[] msg;
				byte[] sig;
				in.readFully(inputByte, 0, lenght);
				decipherInput = decrypt(inputByte, privKey);
				msg = Arrays.copyOfRange(decipherInput, 0, msgLenght);
				sig = Arrays.copyOfRange(decipherInput, msgLenght, decipherInput.length);

				System.out.println("################################################");
				System.out.println("RECEIVED MSG:");
				System.out.println(new String(inputByte, "UTF-8"));
				System.out.println("================================================");
				System.out.println("DECRYPTED MSG:");
				System.out.println(new String(msg, "UTF-8"));
				System.out.println("================================================");
				System.out.println("SIGNATURE:");
				System.out.println(new String(sig, "UTF-8"));
				System.out.println("################################################");
				System.out.println("");
				
				String input = new String (msg, "UTF-8");
				
				int proposedCounter;
				switch (input) {
					case "counter":
        				out.writeInt(counter);
        			break;
        			
					case "username":						
						msgLenght = in.readInt();
						lenght = in.readInt();
						inputByte = new byte[lenght];
						in.readFully(inputByte, 0, lenght);
						decipherInput = decrypt(inputByte, privKey);
						msg = Arrays.copyOfRange(decipherInput, 0, msgLenght);
						sig = Arrays.copyOfRange(decipherInput, msgLenght, decipherInput.length);
						
						input = new String (msg, "UTF-8");
						clientUsername = input;
						
						System.out.println("################################################");
						System.out.println("RECEIVED MSG:");
						System.out.println(new String(inputByte, "UTF-8"));
						System.out.println("================================================");
						System.out.println("DECRYPTED MSG:");
						System.out.println(new String(msg, "UTF-8"));
						System.out.println("================================================");
						System.out.println("SIGNATURE:");
						System.out.println(new String(sig, "UTF-8"));
						System.out.println("################################################");
						System.out.println("");
						
						break;
						
					case "time":
						sendClock();
						break;

					case "register":
						proposedCounter = in.readInt();
						if (calculateCounter() != proposedCounter) {
							throw new Exception();
						}
						else{
							counter = proposedCounter;
							msgLenght = in.readInt();
							lenght = in.readInt();
							inputByte = new byte[lenght];
							in.readFully(inputByte, 0, lenght);
							decipherInput = decrypt(inputByte, privKey);
							msg = Arrays.copyOfRange(decipherInput, 0, msgLenght);
							sig = Arrays.copyOfRange(decipherInput, msgLenght, decipherInput.length);
							
							System.out.println("################################################");
							System.out.println("RECEIVED MSG:");
							System.out.println(new String(inputByte, "UTF-8"));
							System.out.println("================================================");
							System.out.println("DECRYPTED MSG:");
							System.out.println(new String(msg, "UTF-8"));
							System.out.println("================================================");
							System.out.println("SIGNATURE:");
							System.out.println(new String(sig, "UTF-8"));
							System.out.println("################################################");
							System.out.println("");
							
	            			register(receivePublicKey(), sig);
						}

						break;

					case "put":
						
						proposedCounter = in.readInt();
						if (proposedCounter != calculateCounter()) {
							throw new Exception();
						}
						else{
							counter = proposedCounter;
							byte[] putDomain, putUsername, putPass;
							System.out.println(input);
	
							msgLenght = in.readInt();
							lenght = in.readInt();
							inputByte = new byte[lenght];
							in.readFully(inputByte, 0, lenght);
							decipherInput = decrypt(inputByte, privKey);
							msg = Arrays.copyOfRange(decipherInput, 0, msgLenght);
							sig = Arrays.copyOfRange(decipherInput, msgLenght, decipherInput.length);
							
							if(!verifySignature(sig, msg)) {
								System.out.println("Signatured not verified");
								break;
							}
							
							putDomain = msg;
							input = new String (msg, "UTF-8");
							
							System.out.println("################################################");
							System.out.println("RECEIVED MSG:");
							System.out.println(new String(inputByte, "UTF-8"));
							System.out.println("================================================");
							System.out.println("DECRYPTED MSG:");
							System.out.println(new String(msg, "UTF-8"));
							System.out.println("================================================");
							System.out.println("SIGNATURE:");
							System.out.println(new String(sig, "UTF-8"));
							System.out.println("################################################");
							System.out.println("");
							
							msgLenght = in.readInt();
							lenght = in.readInt();
							inputByte = new byte[lenght];
							in.readFully(inputByte, 0, lenght);
							decipherInput = decrypt(inputByte, privKey);
							msg = Arrays.copyOfRange(decipherInput, 0, msgLenght);
							sig = Arrays.copyOfRange(decipherInput, msgLenght, decipherInput.length);
							
							if(!verifySignature(sig, msg)) {
								System.out.println("Signatured not verified");
								break;
							}
							
							putUsername = msg;
							input = new String (msg, "UTF-8");
							
							System.out.println("################################################");
							System.out.println("RECEIVED MSG:");
							System.out.println(new String(inputByte, "UTF-8"));
							System.out.println("================================================");
							System.out.println("DECRYPTED MSG:");
							System.out.println(new String(msg, "UTF-8"));
							System.out.println("================================================");
							System.out.println("SIGNATURE:");
							System.out.println(new String(sig, "UTF-8"));
							System.out.println("################################################");
							System.out.println("");
							
							lenght = in.readInt();
							inputByte = new byte[lenght]; 
							in.readFully(inputByte, 0, inputByte.length);
							putPass = inputByte;
							
							System.out.println("################################################");
							System.out.println("RECEIVED PASS:");
							System.out.println(new String(inputByte, "UTF-8"));
							System.out.println("################################################");
							System.out.println("");

							put(getPublicKey(sig), putDomain, putUsername, putPass, sig);
						}

						break;

					case "get":
						proposedCounter = in.readInt();
						//System.out.println(proposedCounter);
						if (proposedCounter != calculateCounter()) {
							throw new Exception();
						}
						else{
							byte[] getDomain, getUsername;
							counter = proposedCounter;
		
							msgLenght = in.readInt();
							lenght = in.readInt();
							inputByte = new byte[lenght];
							in.readFully(inputByte, 0, lenght);
							decipherInput = decrypt(inputByte, privKey);
							msg = Arrays.copyOfRange(decipherInput, 0, msgLenght);
							sig = Arrays.copyOfRange(decipherInput, msgLenght, decipherInput.length);
							
							if(!verifySignature(sig, msg)) {
								System.out.println("Signature not verified");
								break;
							}
							
							getDomain = msg;
							input = new String (msg, "UTF-8");
							
							System.out.println("################################################");
							System.out.println("RECEIVED MSG:");
							System.out.println(new String(inputByte, "UTF-8"));
							System.out.println("================================================");
							System.out.println("DECRYPTED MSG:");
							System.out.println(new String(msg, "UTF-8"));
							System.out.println("================================================");
							System.out.println("SIGNATURE:");
							System.out.println(new String(sig, "UTF-8"));
							System.out.println("################################################");
							System.out.println("");
							
							msgLenght = in.readInt();
							lenght = in.readInt();
							inputByte = new byte[lenght];
							in.readFully(inputByte, 0, lenght);
							decipherInput = decrypt(inputByte, privKey);
							msg = Arrays.copyOfRange(decipherInput, 0, msgLenght);
							sig = Arrays.copyOfRange(decipherInput, msgLenght, decipherInput.length);
							
							if(!verifySignature(sig, msg)) {
								System.out.println("Signatured not verified");
								break;
							}
							
							getUsername = msg;
							input = new String (msg, "UTF-8");
							
							System.out.println("################################################");
							System.out.println("RECEIVED MSG:");
							System.out.println(new String(inputByte, "UTF-8"));
							System.out.println("================================================");
							System.out.println("DECRYPTED MSG:");
							System.out.println(new String(msg, "UTF-8"));
							System.out.println("================================================");
							System.out.println("SIGNATURE:");
							System.out.println(new String(sig, "UTF-8"));
							System.out.println("################################################");
							System.out.println("");
							
							if(!verifySignature(sig, msg)) {
								System.out.println("Signatured not verified");
								break;
							}
	
							get(getPublicKey(sig), getDomain, getUsername, sig);
						}
						break;

					default:
						break;
				}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				System.out.println("Connection with client " + clientUsername + " severed");
				e.printStackTrace();
				return;
			}
		}
	}

	public void register(Key publicKey, byte[] signature) {
		//dir.mkdir();
		//File file = new File(clientUsername + File.separator +  "publicKey");
		File dir = new File(clientUsername);
		if (dir.mkdir()) {}
		else { System.out.println("User already registered"); }

		String key = DatatypeConverter.printHexBinary(publicKey.getEncoded());
		FileOutputStream keyfos;
		try {
			keyfos = new FileOutputStream(clientUsername + File.separator + "publicKey");
			keyfos.write(key.getBytes());
			keyfos.write(signature);
			
			System.out.println("################################################");
			System.out.println(clientUsername + " Registered");
			System.out.println("################################################");
			System.out.println("");
			
			keyfos.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
	}

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password, byte[] signature) {
		try {
			String bar =""+ '#';
			String _domain = new String(domain, "UTF-8");
			String _username = new String(username, "UTF-8");
			String filename = _domain + bar + _username;
			
			FileOutputStream fos = new FileOutputStream(clientUsername + File.separator + filename);
			
			System.out.println("################################################");
			System.out.println("Saving password with code " + _domain + bar + _username + " for " + clientUsername);
			System.out.println("PASS:");
			System.out.println(new String(password, "UTF-8"));
			System.out.println("################################################");
			System.out.println("");
			
			fos.write(password);
			fos.write(signature);
			fos.close();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username, byte[] signature) throws Exception {
		byte[] fail = "NULL".getBytes("UTF-8");
		
		String bar =""+ '#';
		String _domain = new String(domain, "UTF-8");
		String _username = new String(username, "UTF-8");
		String filename = _domain + bar + _username;
		
		File file = new File(clientUsername + File.separator + filename);
		File dir = new File(clientUsername);
		for(File f : dir.listFiles()) {
			if(f.getName().equalsIgnoreCase(filename)) {
				FileInputStream fis = new FileInputStream(file);
				byte[] output = new byte [fis.available() - signature.length];
				fis.read(output);
				fis.close();
				
				out.flush();
				out.writeInt(output.length);
				System.out.println("################################################");
				System.out.println("sending password of " + _domain + bar+_username + " to " + clientUsername);
				System.out.println("PASS:");
				System.out.println(new String(output, "UTF-8"));
				System.out.println("################################################");
				System.out.println("");

				out.write(output);
				return output;
			}
		}
		
		System.out.println("No password stored under this domain/username");
		out.flush();
		out.writeInt(fail.length);
		out.write(fail);
		return null;	
	}


	public Key getPublicKey(byte[] signature){
		Key output = null;

		try {
			/*scan = new Scanner(new File(clientUsername));
			scan.useDelimiter(Pattern.compile("\n"));
	    	String logicalLine = scan.next();
	    	scan.close();*/
			
			File file = new File(clientUsername + File.separator + "publicKey");
			FileInputStream fis = new FileInputStream(file);
			byte[] outputbytes = new byte [fis.available() - signature.length];
			fis.read(outputbytes);
			
			String aux = new String(outputbytes, "UTF-8");
			System.out.println("PUBLIC KEY: " + aux);
			
	    	output = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(DatatypeConverter.parseHexBinary(aux)));
	    	fis.close();
	    	
			/*BufferedReader brTest = new BufferedReader(new FileReader(clientUsername + File.separator + "publicKey"));
    		String text = brTest.readLine();

	    	output = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(DatatypeConverter.parseHexBinary(text)));
	    	brTest.close();*/
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

	/*
	* Auxiliary function to read and convert the public key
	*
	*/
	public Key receivePublicKey(){
		Key pubKey = null;

		byte[] lenb = new byte[8];
        try {
			socket.getInputStream().read(lenb,0,8);
			
	        ByteBuffer bb = ByteBuffer.wrap(lenb);
	        int len = bb.getInt();

	        byte[] pubKeyBytes = new byte[len];
	        socket.getInputStream().read(pubKeyBytes);
	        X509EncodedKeySpec ks = new X509EncodedKeySpec(pubKeyBytes);
	            			
	        KeyFactory kf = KeyFactory.getInstance("RSA");
	        pubKey = kf.generatePublic(ks);  			
       
        } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 	
        return pubKey;
	}

	public void sendClock(){
		long actualTime = System.currentTimeMillis();
		String forprint = "" + actualTime;
		try {
			out.flush();
			System.out.println("Sending time: " + forprint);
			out.writeLong(actualTime);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public int calculateCounter(){
		//System.out.println(counter);
		return counter+42;
	}


	public Key getServerKey(String str){
		Key output = null;

		try {
			
			String pass= "pass";
	    	FileInputStream fis = new java.io.FileInputStream("ServerKeys");
	    	KeyStore sk = KeyStore.getInstance("JKS");
	        //gets keystore if it already exists
	        sk.load(fis, pass.toCharArray());
	        System.out.println("KeyStore loaded");
	        
	        Key serverPriv = sk.getKey("ServerKeys", pass.toCharArray());
	        Key serverPub = sk.getCertificate("ServerKeys").getPublicKey();			
			
			if(str.equals("pub")){
				output = serverPub;
				fis.close();
	    	}
	    	else if(str.equals("priv")){
				output=serverPriv;
	    		fis.close();
	    	}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return output;
	}
	
  	public static byte[] decrypt(byte[] text, Key key) {
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

    	return dectyptedText;
  	}
  	
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
  	
  	public boolean verifySignature(byte[] sig, byte[] data){
  		boolean verifies = false;
	  	try {
			Signature rsaForVerify = Signature.getInstance("SHA256withRSA");
			rsaForVerify.initVerify((PublicKey) getPublicKey(sig));
			rsaForVerify.update(data);
			verifies = rsaForVerify.verify(sig);
			System.out.println("Signature verifies: " + verifies);
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return verifies;
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