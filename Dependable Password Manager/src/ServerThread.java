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
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.zip.Deflater;

import javax.xml.bind.DatatypeConverter;

import java.nio.ByteBuffer;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ServerThread extends Thread {

	private Socket socket = null;
	static SecretKey sessionKey;
	IvParameterSpec iv;
	private String clientUsername = "";
	static Key privKey;
	static Key pubKey;
	DataOutputStream out;
	int counter = 1 + (int)(Math.random() * 100000);

	public ServerThread(Socket socket) {

		super("MiniServer");
		this.socket = socket;
		privKey = getServerKey("priv");
		pubKey = getServerKey("pub");

	}

	public void run() {

		try {
			out = new DataOutputStream(this.socket.getOutputStream());

			DataInputStream in = new DataInputStream(socket.getInputStream());
			
			// checking for username
//============================================================================================================================================
			int msgLenght;
			int lenght;
			int crLength;
			int proposedCounter;
			byte[] inputByte;
			byte[] decipherInput;
			byte[] msg;
			byte[] counterBytes;
			byte[] cipherMsg;
			byte[] sig;
			byte[] sigPart;
			byte[] cipherSig;
			Key k;
			
			k = receivePublicKey();

			lenght = in.readInt();
			msgLenght = in.readInt();
			inputByte = new byte[lenght];
			
			in.readFully(inputByte, 0, lenght);
			System.out.println("DEBUG: " + 1);
			cipherMsg = Arrays.copyOfRange(inputByte, 0, msgLenght);
			cipherSig = Arrays.copyOfRange(inputByte, msgLenght, lenght);
			msg = decrypt(cipherMsg, privKey);
			sig = decrypt(cipherSig, privKey);
			
			inputByte = new byte[256];
			in.readFully(inputByte, 0, 256);
			System.out.println("DEBUG: " + 2);
			sigPart = decrypt(inputByte, privKey);
			sig = concatenate(sig, sigPart);
			
			if (!verifySignature(k, sig, msg)) {
				System.out.println("Signature not verified, username not registered");
				out.close();
				in.close();
				return;
			}

			String input = new String(msg, "UTF-8");
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
//======================================================================================================================================
			// generating sessionKey
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			sessionKey = keyGen.generateKey();

			// build the initialization vector (randomly).
			SecureRandom random = new SecureRandom();
			byte ivaux[] = new byte[16];// generate random 16 byte IV AES is						
			random.nextBytes(ivaux);// always 16bytes
			iv = new IvParameterSpec(ivaux);
			
			byte[] msgSign1= encrypt(Base64.getDecoder().decode(Base64.getEncoder().encodeToString(sessionKey.getEncoded())), k);
			byte[] sig0= signature(Base64.getDecoder().decode(Base64.getEncoder().encodeToString(sessionKey.getEncoded())));
			byte[] sigPart1 = encrypt(Arrays.copyOfRange(sig0, 0, (sig0.length/2)), k);
			byte[] sigPart2 = encrypt(Arrays.copyOfRange(sig0, (sig0.length/2), sig0.length), k);
			byte[] sessionCipher= concatenate(msgSign1, sigPart1);
			out.writeInt(sessionCipher.length);
			out.writeInt(msgSign1.length);
			out.write(sessionCipher);
			out.flush();
			System.out.println("DEBUG: " + sigPart2.length);
			out.write(sigPart2);
			

			msgSign1= encrypt(iv.getIV(), k);
			sig0= signature(iv.getIV());
			sigPart1 = encrypt(Arrays.copyOfRange(sig0, 0, (sig0.length/2)), k);
			sigPart2 = encrypt(Arrays.copyOfRange(sig0, (sig0.length/2), sig0.length), k);
			sessionCipher= concatenate(msgSign1, sigPart1);
			out.writeInt(sessionCipher.length);
			out.writeInt(msgSign1.length);
			out.write(sessionCipher);
			out.flush();
			System.out.println("DEBUG: " + sigPart2.length);
			out.write(sigPart2);
			out.flush();
//==================================================================================================================================
			// sending counter
			out.writeInt(Integer.toString(counter).getBytes("UTF-8").length);
			byte[] msgSign = concatenate(Integer.toString(counter).getBytes("UTF-8"), signature(Integer.toString(counter).getBytes("UTF-8")));// creates
																												// MSG+SIG
			byte[] toSend = sessionEncrypt(sessionKey, iv , msgSign);// Cipher
			out.writeInt(toSend.length);// Sends total length
			out.write(toSend);// Sends {MSG+SIG}serverpubkey
			System.out.println("Challenge Response send");

//============================================================================================================================================			
			while (socket.isConnected()) {
				// preparing variables for command requests
				msgLenght = in.readInt();
				crLength = in.readInt();
				int msgCrLength = in.readInt();
				lenght = in.readInt();
				inputByte = new byte[lenght];
				in.readFully(inputByte, 0, lenght);
				decipherInput = sessionDecrypt(sessionKey, iv, inputByte);
				msg = Arrays.copyOfRange(decipherInput, 0, msgCrLength);
				sig = Arrays.copyOfRange(decipherInput, msgCrLength, decipherInput.length);
				
				if (!verifySignature(k, sig, msg)) {
					System.out.println("Signature not verified, no action taken");
					continue;
				}
				counterBytes = Arrays.copyOfRange(msg, 0, crLength);
				msg = Arrays.copyOfRange(msg, crLength, msgCrLength);
				proposedCounter = Integer.parseInt(new String(counterBytes, "UTF-8"));
				
				if (proposedCounter != calculateCounter()) {
					System.out.println("Challenge Response failed");
					continue;
				}
				counter = proposedCounter;
					
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

				input = new String(msg, "UTF-8");

				switch (input) {

				case "register":
					msgLenght = in.readInt();
					crLength = in.readInt();
					msgCrLength = in.readInt();
					lenght = in.readInt();
					inputByte = new byte[lenght];
					in.readFully(inputByte, 0, lenght);
					decipherInput = sessionDecrypt(sessionKey, iv, inputByte);
					msg = Arrays.copyOfRange(decipherInput, 0, msgCrLength);
					sig = Arrays.copyOfRange(decipherInput, msgCrLength, decipherInput.length);
					
					if (!verifySignature(k, sig, msg)) {
						System.out.println("Signature not verified, no action taken");
						break;
					}
					counterBytes = Arrays.copyOfRange(msg, 0, crLength);
					msg = Arrays.copyOfRange(msg, crLength, msgCrLength);
					proposedCounter = Integer.parseInt(new String(counterBytes, "UTF-8"));
					
					if (proposedCounter != calculateCounter()) {
						System.out.println("Challenge Response failed");
						break;
					}
					counter = proposedCounter;
						
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

					break;

				case "put":

						byte[] putDomain, putUsername, putPass;
						System.out.println(input);

						msgLenght = in.readInt();
						crLength = in.readInt();
						msgCrLength = in.readInt();
						lenght = in.readInt();
						inputByte = new byte[lenght];
						in.readFully(inputByte, 0, lenght);
						decipherInput = sessionDecrypt(sessionKey, iv, inputByte);
						msg = Arrays.copyOfRange(decipherInput, 0, msgCrLength);
						sig = Arrays.copyOfRange(decipherInput, msgCrLength, decipherInput.length);
						
						if (!verifySignature(k, sig, msg)) {
							System.out.println("Signature not verified, no action taken");
							break;
						}
						counterBytes = Arrays.copyOfRange(msg, 0, crLength);
						msg = Arrays.copyOfRange(msg, crLength, msgCrLength);
						proposedCounter = Integer.parseInt(new String(counterBytes, "UTF-8"));
						
						if (proposedCounter != calculateCounter()) {
							System.out.println("Challenge Response failed");
							break;
						}
						counter = proposedCounter;

						putDomain = msg;
						input = new String(msg, "UTF-8");

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
						crLength = in.readInt();
						msgCrLength = in.readInt();
						lenght = in.readInt();
						inputByte = new byte[lenght];
						in.readFully(inputByte, 0, lenght);
						decipherInput = sessionDecrypt(sessionKey, iv, inputByte);
						msg = Arrays.copyOfRange(decipherInput, 0, msgCrLength);
						sig = Arrays.copyOfRange(decipherInput, msgCrLength, decipherInput.length);
						
						if (!verifySignature(k, sig, msg)) {
							System.out.println("Signature not verified, no action taken");
							break;
						}
						counterBytes = Arrays.copyOfRange(msg, 0, crLength);
						msg = Arrays.copyOfRange(msg, crLength, msgCrLength);
						proposedCounter = Integer.parseInt(new String(counterBytes, "UTF-8"));
						
						if (proposedCounter != calculateCounter()) {
							System.out.println("Challenge Response failed");
							break;
						}
						counter = proposedCounter;

						putUsername = msg;
						input = new String(msg, "UTF-8");

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
					

					break;

				case "get":
						byte[] getDomain, getUsername;

						msgLenght = in.readInt();
						crLength = in.readInt();
						msgCrLength = in.readInt();
						lenght = in.readInt();
						inputByte = new byte[lenght];
						in.readFully(inputByte, 0, lenght);
						decipherInput = sessionDecrypt(sessionKey, iv, inputByte);
						msg = Arrays.copyOfRange(decipherInput, 0, msgCrLength);
						sig = Arrays.copyOfRange(decipherInput, msgCrLength, decipherInput.length);
						
						if (!verifySignature(k, sig, msg)) {
							System.out.println("Signature not verified, no action taken");
							break;
						}
						counterBytes = Arrays.copyOfRange(msg, 0, crLength);
						msg = Arrays.copyOfRange(msg, crLength, msgCrLength);
						proposedCounter = Integer.parseInt(new String(counterBytes, "UTF-8"));
						
						if (proposedCounter != calculateCounter()) {
							System.out.println("Challenge Response failed");
							break;
						}
						counter = proposedCounter;
						getDomain = msg;
						input = new String(msg, "UTF-8");

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
						crLength = in.readInt();
						msgCrLength = in.readInt();
						lenght = in.readInt();
						inputByte = new byte[lenght];
						in.readFully(inputByte, 0, lenght);
						decipherInput = sessionDecrypt(sessionKey, iv, inputByte);
						msg = Arrays.copyOfRange(decipherInput, 0, msgCrLength);
						sig = Arrays.copyOfRange(decipherInput, msgCrLength, decipherInput.length);
						
						if (!verifySignature(k, sig, msg)) {
							System.out.println("Signature not verified, no action taken");
							break;
						}
						counterBytes = Arrays.copyOfRange(msg, 0, crLength);
						msg = Arrays.copyOfRange(msg, crLength, msgCrLength);
						proposedCounter = Integer.parseInt(new String(counterBytes, "UTF-8"));
						
						if (proposedCounter != calculateCounter()) {
							System.out.println("Challenge Response failed");
							break;
						}
						counter = proposedCounter;

						getUsername = msg;
						input = new String(msg, "UTF-8");

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

						get(getPublicKey(sig), getDomain, getUsername, sig);
					
					break;

				default:
					break;
				}
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.out.println("Connection with client " + clientUsername + " severed");
			e.printStackTrace();
			return;
		}
	}

	public void register(Key publicKey, byte[] signature) {
		// dir.mkdir();
		// File file = new File(clientUsername + File.separator + "publicKey");
		File dir = new File(clientUsername);
		if (dir.mkdir()) {
		} else {
			System.out.println("User already registered");
		}

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
			
			StringBuilder hexString = new StringBuilder();
			for (int i = 0; i < domain.length; i++)
			  {
			      String hex = Integer.toHexString(0xFF & domain[i]);
			      if (hex.length() == 1)
			          hexString.append('0');

			      hexString.append(hex);
			  }
			
			for (int i = 0; i < username.length; i++)
			  {
			      String hex = Integer.toHexString(0xFF & domain[i]);
			      if (hex.length() == 1)
			          hexString.append('0');

			      hexString.append(hex);
			  }
			
			/*String bar = "" + '#';
			String _domain = new String(domain, "UTF-8");
			String _username = new String(username, "UTF-8");*/
			
			String filename = hexString.toString().toUpperCase();

			FileOutputStream fos = new FileOutputStream(clientUsername + File.separator + filename);

			System.out.println("################################################");
			System.out.println("Saving password with code of client "  + clientUsername);
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
		
		StringBuilder hexString = new StringBuilder();
		for (int i = 0; i < domain.length; i++)
		  {
		      String hex = Integer.toHexString(0xFF & domain[i]);
		      if (hex.length() == 1)
		          hexString.append('0');

		      hexString.append(hex);
		  }
		
		for (int i = 0; i < username.length; i++)
		  {
		      String hex = Integer.toHexString(0xFF & domain[i]);
		      if (hex.length() == 1)
		          hexString.append('0');

		      hexString.append(hex);
		  }

		/*String bar = "" + '#';
		String _domain = new String(domain, "UTF-8");
		String _username = new String(username, "UTF-8");*/
		String filename = hexString.toString().toUpperCase();

		File file = new File(clientUsername + File.separator + filename);
		File dir = new File(clientUsername);
		for (File f : dir.listFiles()) {
			if (f.getName().equalsIgnoreCase(filename)) {
				FileInputStream fis = new FileInputStream(file);
				byte[] pass = new byte[fis.available() - signature.length];
				fis.read(pass);
				fis.close();

				byte[] sig = signature(pass);
				byte[] output = sessionEncrypt(sessionKey, iv, concatenate(pass, sig));

				out.flush();
				out.writeInt(pass.length);
				out.writeInt(output.length);
				System.out.println("################################################");
				System.out.println("sending password to " + clientUsername);
				System.out.println("PASS:");
				System.out.println(new String(pass, "UTF-8"));
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

	public Key getPublicKey(byte[] signature) {
		Key output = null;

		try {
			/*
			 * scan = new Scanner(new File(clientUsername));
			 * scan.useDelimiter(Pattern.compile("\n")); String logicalLine =
			 * scan.next(); scan.close();
			 */

			File file = new File(clientUsername + File.separator + "publicKey");
			FileInputStream fis = new FileInputStream(file);
			byte[] outputbytes = new byte[fis.available() - signature.length];
			fis.read(outputbytes);

			String aux = new String(outputbytes, "UTF-8");
			System.out.println("PUBLIC KEY: " + aux);

			output = KeyFactory.getInstance("RSA")
					.generatePublic(new X509EncodedKeySpec(DatatypeConverter.parseHexBinary(aux)));
			fis.close();

			/*
			 * BufferedReader brTest = new BufferedReader(new
			 * FileReader(clientUsername + File.separator + "publicKey"));
			 * String text = brTest.readLine();
			 * 
			 * output = KeyFactory.getInstance("RSA").generatePublic(new
			 * X509EncodedKeySpec(DatatypeConverter.parseHexBinary(text)));
			 * brTest.close();
			 */
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
	public Key receivePublicKey() {
		Key pubKey = null;

		byte[] lenb = new byte[8];
		try {
			socket.getInputStream().read(lenb, 0, 8);

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

	public void sendClock() {
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

	public int calculateCounter() {
		// System.out.println(counter);
		return counter + 42;
	}

	public Key getServerKey(String str) {
		Key output = null;

		try {

			String pass = "pass";
			FileInputStream fis = new java.io.FileInputStream("ServerKeys");
			KeyStore sk = KeyStore.getInstance("JKS");
			// gets keystore if it already exists
			sk.load(fis, pass.toCharArray());
			System.out.println("KeyStore loaded");

			Key serverPriv = sk.getKey("ServerKeys", pass.toCharArray());
			Key serverPub = sk.getCertificate("ServerKeys").getPublicKey();

			if (str.equals("pub")) {
				output = serverPub;
				fis.close();
			} else if (str.equals("priv")) {
				output = serverPriv;
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

	public static byte[] encrypt(byte[] text, Key key) {
		byte[] cipherText = null;
		try {
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance("RSA");
			// encrypt the plain text using the public key
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherText = cipher.doFinal(text);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return cipherText;
	}

	public static byte[] sessionEncrypt(SecretKey skeySpec, IvParameterSpec iv, byte[] value) {
		try {

			SecretKeySpec sk = new SecretKeySpec(skeySpec.getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, sk, iv);

			byte[] encrypted = cipher.doFinal(value);
			System.out.println("encrypted string: " + new String(encrypted, "UTF-8"));

			return encrypted;
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}

	public static byte[] sessionDecrypt(SecretKey skeySpec, IvParameterSpec iv, byte[] encrypted) {
		try {

			SecretKeySpec sk = new SecretKeySpec(skeySpec.getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, sk, iv);

			byte[] original = cipher.doFinal(encrypted);

			return original;
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}

	public byte[] signature(byte[] array) {
		byte[] signature = null;
		Signature rsaForSign;
		try {
			rsaForSign = Signature.getInstance("MD2withRSA");
			rsaForSign.initSign((PrivateKey) privKey);
			rsaForSign.update(array);
			signature = rsaForSign.sign();
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return signature;
	}

	public boolean verifySignature(Key key, byte[] sig, byte[] data) {
		boolean verifies = false;
		try {
			Signature rsaForVerify = Signature.getInstance("MD2withRSA");
			rsaForVerify.initVerify((PublicKey) key);
			rsaForVerify.update(data);
			verifies = rsaForVerify.verify(sig);
			System.out.println("Signature verifies: " + verifies);
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return verifies;
	}

	public byte[] concatenate(byte[] a, byte[] b) {
		byte c[] = null;

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		try {
			outputStream.write(a);
			outputStream.write(b);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		c = outputStream.toByteArray();

		return c;
	}
}