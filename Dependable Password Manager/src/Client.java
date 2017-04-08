import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.*;

public class Client {

	DataOutputStream out;
	DataInputStream in;
	int counter;
	static Key pubKey;
	static Key privKey;
	static Key serverPubKey;
	static Socket clientSocket = null;
	static String username = null;
	static String password = null;

	public Client(String username, String password) throws IOException, UnknownHostException {
		clientSocket = new Socket("localhost", 8080);
		out = new DataOutputStream(clientSocket.getOutputStream());
		in = new DataInputStream(clientSocket.getInputStream());
		sendUsername();
		askServerClock();
	}

	public static void main(String[] args) {

		Client client = null;

		// establishing connection with server
		while (true) {
			System.out.println("==Welcome to your Password Manager==");
			System.out.print("Insert your Username: ");
			username = System.console().readLine();
			System.out.print("Insert your Password: ");
			password = System.console().readLine();

			KeyStore ks = null;

			System.out.println("Initializing....");
			try {
				ks = KeyStore.getInstance("JKS");
				serverPubKey = getServerKey();
				init(ks, username, password);
				client = new Client(username, password);
				System.out.println("Please write");
				break;
			} catch (KeyStoreException e) {
				System.out.println("KeyStoreException, please try again");
			} catch (WrongPasswordException e) {
				System.out.println("Wrong Password, please try again");
			} catch (UnknownHostException e) {
				System.out.println("Connection problems, please try again later");
			} catch (IOException e) {
				System.out.println("Connection problems, please try again later");
			}
		}

		// connection established, waiting for client commands
		try {
			while (true) {

				System.out.println("====Please type the desired command or type help for the list of commands====");
				String command = System.console().readLine();
				switch (command) {

				case "register":
					if (pubKey != null) {
						client.register_user();
					}

					break;

				case "put":
					String a;
					byte[] putdomain, putusername, putpassword;
					System.out.println("Insert the desired domain:");
					a = System.console().readLine();
					putdomain = hashCode(a).getBytes("UTF-8");
					System.out.println("Insert the desired username:");
					a = System.console().readLine();
					putusername = hashCode(a).getBytes("UTF-8");
					System.out.println("Insert the desired password:");
					putpassword = encrypt(System.console().readLine().getBytes("UTF-8"), pubKey);
					System.out.println("Ciphering password witn Client Public Key");

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

				case "help":
					System.out.println("Commands available:");
					System.out.println("1 - register");
					System.out.println("2 - put");
					System.out.println("3 - get");
					System.out.println("4 - close");
					break;

				case "close":
					close();
					return;
				default:
					System.out.println("Invalid Command");
					break;
				}

			}
		} catch (IOException e) {
			System.out.println("Connection with server lost. Shutting down...");
		}
	}

	public static void close() throws IOException {
		System.out.println("Closing connection...");
		clientSocket.close();
	}

	public void sendUsername() throws IOException {

		out.flush();
		out.writeInt("username".getBytes("UTF-8").length);// Sends length of
															// msg
		byte[] msgSign = concatenate("username".getBytes("UTF-8"), signature("username".getBytes("UTF-8")));// creates
																											// MSG+SIG
		byte[] toSend = encrypt(msgSign, getServerKey());// Cipher
		out.writeInt(toSend.length);// Sends total length
		out.write(toSend);// Sends {MSG+SIG}serverpubkey

		out.flush();
		out.writeInt(username.getBytes("UTF-8").length);// Sends length of
														// msg
		msgSign = concatenate(username.getBytes("UTF-8"), signature(username.getBytes("UTF-8")));// creates
																									// MSG+SIG
		toSend = encrypt(msgSign, getServerKey());// Cipher
		out.writeInt(toSend.length);// Sends total length
		out.write(toSend);// Sends {MSG+SIG}serverpubkey
	}

	public void askServerClock() throws IOException {

		System.out.println("Asking for Challenge-Response");
		out.flush();
		out.writeInt("counter".getBytes("UTF-8").length);// Sends length of
															// msg
		byte[] msgSign = concatenate("counter".getBytes("UTF-8"), signature("username".getBytes("UTF-8")));// creates
																											// MSG+SIG
		byte[] toSend = encrypt(msgSign, getServerKey());// Cipher
		out.writeInt(toSend.length);// Sends total length
		out.write(toSend);// Sends {MSG+SIG}serverpubkey

		counter = in.readInt();
		System.out.println("Challenge-Response: " + counter);
	}

	public static void init(KeyStore ks, String username, String password) throws WrongPasswordException {

		java.io.FileInputStream fis = null;
		try {
			fis = new java.io.FileInputStream(username + "KeyStore");
			// gets keystore if it already exists
			ks.load(fis, password.toCharArray());
			System.out.println("KeyStore loaded");

			privKey = ks.getKey(username, password.toCharArray());
			pubKey = ks.getCertificate(username).getPublicKey();

		} catch (IOException e) {
			File folder = new File(".");
			File[] listOfFiles = folder.listFiles();

			for (int i = 0; i < listOfFiles.length; i++) {
				if (listOfFiles[i].getName().equals(username + "KeyStore")) {
					System.out.println("Wrong Password, try again");
					throw new WrongPasswordException();
				}
			}

			createNewKeyStore(ks, fis, username, password);

		} catch (NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | KeyStoreException e) {
			e.printStackTrace();
		}

	}

	public static void createNewKeyStore(KeyStore ks, java.io.FileInputStream fis, String username, String password) {

		try {

			ks.load(null, password.toCharArray());

			System.out.println("Created new KeyStore");
			System.out.println("Don't forget to Register");

			// Create keys and store in keystore
			KeyPair kp = createKeyPair();

			GenCert gen = new GenCert();
			X509Certificate[] certificate = gen.generateCertificate(kp);

			ks.setKeyEntry(username, kp.getPrivate(), password.toCharArray(), certificate);

			privKey = kp.getPrivate();
			pubKey = ks.getCertificate(username).getPublicKey();

			// give key store same name as user?
			java.io.FileOutputStream fos = new java.io.FileOutputStream(username + "KeyStore");
			ks.store(fos, password.toCharArray());

		} catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static KeyPair createKeyPair() {
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

	// USES PUBLIC KEY
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

	// USES PRIVATE KEY
	public static byte[] decrypt(byte[] text, Key key) {
		byte[] decryptedText = null;
		try {
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance("RSA");

			// decrypt the text using the private key
			cipher.init(Cipher.DECRYPT_MODE, key);
			decryptedText = cipher.doFinal(text);

		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return decryptedText;
	}

	// HASH CODE
	public static String hashCode(String str) {
		int hash = 7;
		for (int i = 0; i < str.length(); i++) {
			hash = hash * 31 + str.charAt(i);
		}

		System.out.println("Hashing: " + str + " to " + hash);
		return "" + hash;

	}

	public void register_user() throws IOException {

		ByteBuffer bb = ByteBuffer.allocate(8);
		bb.putInt(pubKey.getEncoded().length);
		System.out.println("=============================================================");
		System.out.println("Sending request to register");
		out.flush();
		out.writeInt("register".getBytes("UTF-8").length);// Sends length of
															// msg
		System.out.println("Signing Request with Client Private Key");
		byte[] msgSign = concatenate("register".getBytes("UTF-8"), signature("register".getBytes("UTF-8")));// creates
																											// MSG+SIG
		System.out.println("=============================================================");
		System.out.println("Request Sign: " + (new String(msgSign)));
		System.out.println("Ciphering signed request, using server public key");
		System.out.println("=============================================================");
		byte[] toSend = encrypt(msgSign, getServerKey());// Cipher
		System.out.println("Ciphered signed request: " + (new String(toSend)));
		out.writeInt(toSend.length);// Sends total length
		out.write(toSend);// Sends {MSG+SIG}serverpubkey
		System.out.println("Request Sent");

		System.out.println("=============================================================");
		System.out.println("Request done! Doing Challenge-Response");
		out.writeInt(calculateCounter());
		System.out.println("=============================================================");
		out.flush();

		System.out.println("=============================================================");
		System.out.println("Sending username: " + username);
		out.writeInt(username.getBytes("UTF-8").length);// Sends length of
														// msg
		System.out.println("Signing Username with Client Private Key");
		msgSign = concatenate(username.getBytes("UTF-8"), signature(username.getBytes("UTF-8")));// creates
																									// MSG+SIG
		System.out.println("=============================================================");
		System.out.println("Username Sign: " + (new String(msgSign)));
		System.out.println("Ciphering username, using server public key");
		System.out.println("=============================================================");
		toSend = encrypt(msgSign, getServerKey());// Cipher
		System.out.println("Ciphered signed username: " + (new String(toSend)));
		out.writeInt(toSend.length);// Sends total length
		out.write(toSend);// Sends {MSG+SIG}serverpubkey
		System.out.println("Username Sent");

		System.out.println("=============================================================");
		clientSocket.getOutputStream().write(bb.array());
		clientSocket.getOutputStream().write(pubKey.getEncoded());
		clientSocket.getOutputStream().flush();
	}

	public void save_password(byte[] domain, byte[] username, byte[] password) {
		try {

			System.out.println("=============================================================");
			System.out.println("Sending request to save password");
			out.flush();
			out.writeInt("put".getBytes("UTF-8").length);// Sends length of msg
			System.out.println("Signing Request with Client Private Key");
			byte[] msgSign = concatenate("put".getBytes("UTF-8"), signature("put".getBytes("UTF-8")));// creates
																										// MSG+SIG
			System.out.println("=============================================================");
			System.out.println("Request Sign: " + (new String(msgSign)));
			System.out.println("Ciphering signed request, using server public key");
			System.out.println("=============================================================");
			byte[] toSend = encrypt(msgSign, getServerKey());// Cipher
			System.out.println("Ciphered signed request: " + (new String(toSend)));
			out.writeInt(toSend.length);// Sends total length
			out.write(toSend);// Sends {MSG+SIG}serverpubkey
			System.out.println("Request Sent");

			System.out.println("=============================================================");
			System.out.println("Request done! Doing Challenge-Response");
			out.writeInt(calculateCounter());
			System.out.println("=============================================================");

			System.out.println("Sending domain: " + (new String(domain, "UTF-8")));
			out.flush();
			out.writeInt(domain.length);// Sends length of msg
			System.out.println("Signing Domain with Client Private Key");
			msgSign = concatenate(domain, signature(domain));// creates MSG+SIG
			System.out.println("=============================================================");
			System.out.println("Domain Sign: " + (new String(msgSign)));
			System.out.println("Ciphering domain, using server public key");
			System.out.println("=============================================================");
			toSend = encrypt(msgSign, getServerKey());// Cipher
			System.out.println("Ciphered signed domain: " + (new String(toSend)));
			out.writeInt(toSend.length);// Sends total length
			out.write(toSend);// Sends {MSG+SIG}serverpubkey
			System.out.println("Domain Sent");

			System.out.println("=============================================================");
			System.out.println("Sending username: " + (new String(username, "UTF-8")));
			out.flush();
			out.writeInt(username.length);// Sends length of msg
			System.out.println("Signing username with Client Private Key");
			msgSign = concatenate(username, signature(username));// creates
																	// MSG+SIG
			System.out.println("=============================================================");
			System.out.println("Username Sign: " + (new String(msgSign)));
			System.out.println("Ciphering username, using server public key");
			System.out.println("=============================================================");
			toSend = encrypt(msgSign, getServerKey());// Cipher
			System.out.println("Ciphered signed username: " + (new String(toSend)));
			out.writeInt(toSend.length);// Sends total length
			out.write(toSend);
			System.out.println("Username Sent");

			System.out.println("=============================================================");
			System.out.println("Sending Ciphered Password");
			out.flush();
			out.writeInt(password.length);
			out.write(password);
			System.out.println("Password Sent");
			System.out.println("=============================================================");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void retrieve_password(byte[] domain, byte[] username) {
		byte[] inputByte = null;
		try {
			System.out.println("=============================================================");
			System.out.println("Sending request to retrieve password");
			out.flush();
			out.writeInt("get".getBytes("UTF-8").length);// Sends length of msg
			System.out.println("Signing Request with Client Private Key");
			byte[] msgSign = concatenate("get".getBytes("UTF-8"), signature("get".getBytes("UTF-8")));// creates
																										// MSG+SIG
			System.out.println("=============================================================");
			System.out.println("Request Sign: " + (new String(msgSign)));
			System.out.println("Ciphering signed request, using server public key");
			System.out.println("=============================================================");
			byte[] toSend = encrypt(msgSign, getServerKey());// Cipher
			System.out.println("Ciphered signed request: " + (new String(toSend)));
			out.writeInt(toSend.length);// Sends total length
			out.write(toSend);// Sends {MSG+SIG}serverpubkey
			System.out.println("Request Sent");

			System.out.println("=============================================================");
			System.out.println("Request done! Doing Challenge-Response");
			out.writeInt(calculateCounter());
			System.out.println("=============================================================");

			System.out.println("Sending domain: " + (new String(domain, "UTF-8")));
			out.flush();
			out.writeInt(domain.length);// Sends length of msg
			System.out.println("Signing Domain with Client Private Key");
			msgSign = concatenate(domain, signature(domain));// creates MSG+SIG
			System.out.println("=============================================================");
			System.out.println("Domain Sign: " + (new String(msgSign)));
			System.out.println("Ciphering domain, using server public key");
			System.out.println("=============================================================");
			toSend = encrypt(msgSign, getServerKey());// Cipher
			System.out.println("Ciphered signed domain: " + (new String(toSend)));
			out.writeInt(toSend.length);// Sends total length
			out.write(toSend);// Sends {MSG+SIG}serverpubkey
			System.out.println("Domain Sent");

			System.out.println("=============================================================");
			System.out.println("Sending username: " + (new String(username, "UTF-8")));
			out.flush();
			out.writeInt(username.length);// Sends length of msg
			System.out.println("Signing username with Client Private Key");
			msgSign = concatenate(username, signature(username));// creates
																	// MSG+SIG
			System.out.println("=============================================================");
			System.out.println("Username Sign: " + (new String(msgSign)));
			System.out.println("Ciphering username, using server public key");
			System.out.println("=============================================================");
			toSend = encrypt(msgSign, getServerKey());// Cipher
			System.out.println("Ciphered signed username: " + (new String(toSend)));
			out.writeInt(toSend.length);// Sends total length
			out.write(toSend);
			System.out.println("Username Sent");

			System.out.println("=============================================================");
			System.out.println("Receiving Password....");
			int passLength = in.readInt();
			int msgLength = in.readInt();
			
			byte[] inputAux = new byte[msgLength];
			in.readFully(inputAux, 0, inputAux.length);
			
			inputByte = Arrays.copyOfRange(inputAux, 0, passLength);
			byte[] sig = Arrays.copyOfRange(inputAux, passLength, msgLength);
			
			if(!verifySignature(sig, inputByte)) {
				System.out.println("Signature not verified, operation aborted");
				return;
			}
		
			// output = in.readLine();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			if (new String(inputByte, "UTF-8").equals("NULL")) {
				System.out.println("No password stored under this domain/username");
			} else {
				System.out.println("The password you requested: " + new String(decrypt(inputByte, privKey), "UTF-8"));
			}
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static Key getServerKey() {
		Key output = null;

		try {
			/*
			 * BufferedReader brTest = new BufferedReader(new
			 * FileReader("serverPubKey")); String text = brTest.readLine();
			 * 
			 * output = KeyFactory.getInstance("RSA").generatePublic(new
			 * X509EncodedKeySpec(DatatypeConverter.parseHexBinary(text)));
			 * brTest.close();
			 */
			String pass = "pass";
			FileInputStream fis = new java.io.FileInputStream("ServerKeys");
			KeyStore sk = KeyStore.getInstance("JKS");
			// gets keystore if it already exists
			sk.load(fis, pass.toCharArray());

			Key serverPriv = sk.getKey("ServerKeys", pass.toCharArray());
			Key serverPub = sk.getCertificate("ServerKeys").getPublicKey();

			// output = KeyFactory.getInstance("RSA").generatePublic(new
			// X509EncodedKeySpec(serverPub.getEncoded()));
			output = serverPub;
			fis.close();

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
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

	public boolean verifySignature(byte[] sig, byte[] data) {
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

	public int calculateCounter() {
		counter += 42;

		System.out.println("Challenge-Response new counter: " + counter);
		return counter;
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
