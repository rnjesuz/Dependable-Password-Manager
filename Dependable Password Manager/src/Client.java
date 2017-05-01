import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Client {

	DataOutputStream out;
	DataInputStream in;
	int counter;
	static Key pubKey; // JESUS PLS
	static SecretKey sessionKey;
	static IvParameterSpec iv;
	static Key privKey;
	static Key serverPubKey;
	static Socket clientSocket = null;
	ArrayList<SecretKey> sessionKeys = new ArrayList<SecretKey>();
	ArrayList<IvParameterSpec> ivs = new ArrayList<IvParameterSpec>();
	ArrayList<Socket> sockets = new ArrayList<Socket>();
	ArrayList<DataOutputStream> outs = new ArrayList<DataOutputStream>();
	ArrayList<DataInputStream> ins = new ArrayList<DataInputStream>();
	ArrayList<Integer> counters = new ArrayList<Integer>();
	ArrayList<Integer> correctionServers = new ArrayList<Integer>();
	ArrayList<Integer> faultyServers = new ArrayList<Integer>();
	ArrayList<String> receivedPasswords = new ArrayList<String>();
	static String username = null;
	static String password = null;

	// for (1,n) regular
	int wts = 0;
	int acks = 0;
	static int N = 5; // number of servers
	static int round = 1; // current command round
	static int serverN = round % N;; // chosen server to be leader

	public Client(String username, String password) throws IOException, UnknownHostException {
		Random rand = new Random();
		// clientSocket = new Socket("localhost", rand.nextInt((8084 - 8080) +
		// 1) + 8080);

		for (int i = 8080; i <= 8084; i++) {
			sockets.add(new Socket("localhost", i));
		}
		System.out.println(sockets.size());
		for (int i = 0; i < sockets.size(); i++) {
			Socket s =  sockets.get(i);
			outs.add(new DataOutputStream(s.getOutputStream()));
			ins.add(new DataInputStream(s.getInputStream()));
		}

		//send pubKey+username
		sendUsername();
		//initiate challenge response handshake
		askServerClock();
		// send client tag
		sendTag();
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

				// do round mod N = i to choose server to connect
				// connected server is leader
				round++;
				serverN = round % N;
				switch (command) {

				case "register":
					if (pubKey != null) {
						client.register_user();
					}

					if (client.acknowledge()) {
						System.out.println("=============================================================");
						System.out.println("REGISTERED");
						System.out.println("=============================================================");
					} else {
						System.out.println("=============================================================");
						System.out.println("NOT REGISTERED, TRY AGAIN");
						System.out.println("=============================================================");
					}
					break;
				
				case "put":
					String a;
					byte[] putdomain, putusername, putpassword;
					System.out.println("Insert the desired domain:");
					a = System.console().readLine();
					putdomain = hashCode(a);
					System.out.println("Insert the desired username:");
					a = System.console().readLine();
					putusername = hashCode(a);
					System.out.println("Insert the desired password:");
					putpassword = encrypt(System.console().readLine().getBytes("UTF-8"), pubKey);
					System.out.println("Ciphering password witn Client Public Key");

					client.save_password(putdomain, putusername, putpassword);

					if (client.acknowledge()) {
						System.out.println("=============================================================");
						System.out.println("PASSWORD SAVED");
						System.out.println("=============================================================");

					} else {
						System.out.println("=============================================================");
						System.out.println("PASSWORD NOT SAVED IN SERVERS, TRY AGAIN");
						System.out.println("=============================================================");
					}

					break;

				case "get":
					String aa;
					byte[] getdomain, getusername;
					System.out.println("Insert the desired domain:");
					aa = System.console().readLine();
					getdomain = hashCode(aa);
					System.out.println("Insert the desired username:");
					aa = System.console().readLine();
					getusername = hashCode(aa);

					client.retrieve_password(getdomain, getusername);
					client.readingConcensus();
					break;

				case "help":
					System.out.println("Commands available:");
					System.out.println("1 - register");
					System.out.println("2 - put");
					System.out.println("3 - get");
					System.out.println("4 - close");
					break;

				case "close":
					client.close();
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

	private void readingConcensus() {
		int consensus = 0;
		for (int i = 0; i < N; i++) {
			for (int j = 0; j < N; j++) {
				if (receivedPasswords.get(i).equals(receivedPasswords.get(j))) {
					consensus++;
				}
			}
			if (consensus > (N / 2)) {
				if (receivedPasswords.get(i).equals("NULL")) {
					System.out.println("No password stored under this domain/username");
					return;
				} else {
					System.out.println("The password you requested: " + receivedPasswords.get(i));
					return;
				}
			}
		}
	}

	public boolean acknowledge() throws IOException {

		DataInputStream in = ins.get(serverN);
		int wtsLength = in.readInt();
		int msgWtsLength = in.readInt();
		int lenght = in.readInt();
		byte[] inputByte = new byte[lenght];
		in.readFully(inputByte, 0, lenght);
		byte[] decipherInput = sessionDecrypt(sessionKeys.get(serverN), ivs.get(serverN), inputByte);
		byte[] msg = Arrays.copyOfRange(decipherInput, 0, msgWtsLength);
		byte[] sig = Arrays.copyOfRange(decipherInput, msgWtsLength, decipherInput.length);

		if (!verifySignature(sig, msg)) {
			System.out.println("Signature not verified, no action taken");
			return false;
		}

		byte[] wtsBytes = Arrays.copyOfRange(msg, 0, wtsLength);
		msg = Arrays.copyOfRange(msg, wtsLength, msgWtsLength);
		int proposedWts = Integer.parseInt(new String(wtsBytes, "UTF-8"));

		if (wts != proposedWts) {
			System.out.println("something's not right with wts");
			return false;
		} else if (!((new String(msg, "UTF-8")).equals("ack"))) {
			System.out.println("Something went wrong");
			return false;
		} else {
			return true;
		}
	}

	public void close() throws IOException {
		System.out.println("Closing connection...");
		// clientSocket.close();
		for (Socket s : sockets) {
			s.close();
		}
	}

	@SuppressWarnings("null")
	public void sendUsername() throws IOException {
		byte[] msgSign;
		byte[] toSend;
		ByteBuffer bb = ByteBuffer.allocate(8);

		bb.putInt(pubKey.getEncoded().length);

		for (Socket s : sockets) {
			s.getOutputStream().write(bb.array());
			s.getOutputStream().write(pubKey.getEncoded());
		}

		// out.flush();

		byte[] msgSign1 = encrypt(username.getBytes("UTF-8"), getServerKey());
		byte[] sig0 = signature(username.getBytes("UTF-8"));
		byte[] sigPart1 = encrypt(Arrays.copyOfRange(sig0, 0, (sig0.length / 2)), getServerKey());
		byte[] sigPart2 = encrypt(Arrays.copyOfRange(sig0, (sig0.length / 2), sig0.length), getServerKey());
		toSend = concatenate(msgSign1, sigPart1);

		for (DataOutputStream out : outs) {
			out.flush();
			out.writeInt(toSend.length);
			out.writeInt(msgSign1.length);
			out.write(toSend);
			out.flush();
			out.write(sigPart2);
		}

		int lenght = 0;
		int msgLenght = 0;
		byte[] inputByte;
		byte[] cipherMsg;
		byte[] cipherSig;
		byte[] msg;
		byte[] sig;
		byte[] sigPart;
		
		for (int i=0; i<ins.size(); i++) {
			DataInputStream in = ins.get(i);
			lenght = in.readInt();
			msgLenght = in.readInt();
			System.out.println("DEBUG0: " + lenght);
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

			if (!verifySignature(sig, msg)) {
				System.out.println("Signature not verified, username not registered");
				for (DataOutputStream out : outs) {
					out.close();
				}

				for (DataInputStream inn : ins) {
					inn.close();
				}

				return;
			}
			sessionKey = new SecretKeySpec(msg, 0, 16, "AES");
			sessionKeys.add(sessionKey);
		}

		/*
		 * System.out.println("DEBUG: " + 2); byte[] sigPart =
		 * decrypt(inputByte, privKey); sig = concatenate(sig, sigPart);
		 * 
		 * if (!verifySignature(sig, msg)) {
		 * System.out.println("Signature not verified, username not registered"
		 * ); for(DataOutputStream out : outs){ out.close(); }
		 * 
		 * for(DataInputStream in : ins){ in.close(); }
		 * 
		 * return; } sessionKey = new SecretKeySpec(msg, 0, 16, "AES");
		 */

		for (int i=0; i<ins.size(); i++) {
			DataInputStream in = ins.get(i);
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

			if (!verifySignature(sig, msg)) {
				System.out.println("Signature not verified, username not registered");
				for (DataOutputStream out : outs) {
					out.close();
				}

				for (DataInputStream inn : ins) {
					inn.close();
				}
				return;
			}
			IvParameterSpec iv = new IvParameterSpec(msg);
			ivs.add(iv);
		}

		/*
		 * System.out.println("DEBUG: " + 2); sigPart = decrypt(inputByte,
		 * privKey); sig = concatenate(sig, sigPart);
		 * 
		 * if (!verifySignature(sig, msg)) {
		 * System.out.println("Signature not verified, username not registered"
		 * ); for(DataOutputStream out : outs){ out.close(); }
		 * 
		 * for(DataInputStream in : ins){ in.close(); } return; } iv = new
		 * IvParameterSpec(msg);
		 */
	}

	public void askServerClock() throws IOException {

		System.out.println("Asking for Challenge-Response");
		int msgLength = 0;
		int length = 0;
		byte[] inputByte;
		byte[] decipherInput;
		byte[] msg;
		byte[] sig;
		for (int i = 0; i < sessionKeys.size(); i++) {
			SecretKey sk = sessionKeys.get(i);
			DataInputStream in = ins.get(i);
			IvParameterSpec iv = ivs.get(i);

			msgLength = in.readInt();
			length = in.readInt();
			inputByte = new byte[length];
			in.readFully(inputByte, 0, length);
			System.out.println(length);
			decipherInput = sessionDecrypt(sk, iv, inputByte);
			msg = Arrays.copyOfRange(decipherInput, 0, msgLength);
			sig = Arrays.copyOfRange(decipherInput, msgLength, decipherInput.length);

			if (!verifySignature(sig, msg)) {
				System.out.println("Signature not verified, no action taken");
				return;
			}
			counters.add(Integer.parseInt(new String(msg, "UTF-8")));
		}

	}
	
	private void sendTag() throws IOException {
		byte[] msg;
		for (int i = 0; i < sessionKeys.size(); i++) {
			DataOutputStream out = outs.get(i);
			SecretKey sk = sessionKeys.get(i);
			IvParameterSpec iv = ivs.get(i);
			if(serverN == i){
				msg = "lider".getBytes("UTF-8");
			}else{
				msg = "follower".getBytes("UTF-8");
			}
			System.out.println(new String(msg, "UTF-8"));
			counters.set(i, calculateCounter(counters.get(i)));
			byte[] challengeResponse = Integer.toString(counters.get(i)).getBytes("UTF-8");
			out.writeInt(challengeResponse.length);
			byte[] msgCr = concatenate(challengeResponse, msg);
			out.writeInt(msgCr.length);
			System.out.println("Signing Request with Client Private Key");
			byte[] msgSign = concatenate(msgCr, signature(msg));// creates
			byte[] toSend = sessionEncrypt(sk, iv, msgSign);// Cipher
			out.writeInt(toSend.length);// Sends total length
			out.flush();
			out.write(toSend);	
			
			//send 0 to flag we are client
			out.writeInt(0);
		}
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
			kpg.initialize(2048);
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
	public static byte[] hashCode(String str) {
		byte[] response = null;
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			response = digest.digest(str.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return response;
	}

	public void register_user() throws IOException {
		wts += 1;
		for (int i = 0; i < sessionKeys.size(); i++) {
			SecretKey sk = sessionKeys.get(i);
			IvParameterSpec iv = ivs.get(i);
			DataOutputStream out = outs.get(i);
			Socket s = sockets.get(i);

			ByteBuffer bb = ByteBuffer.allocate(8);
			bb.putInt(pubKey.getEncoded().length);
			System.out.println("=============================================================");
			System.out.println("Sending request to register");
			out.flush();
			
			byte[] commandBytes;
			if (i == serverN) {
				// is leader
				commandBytes = "register".getBytes("UTF-8");
				out.writeInt(commandBytes.length);// Sends
																	// length of
			} else {
				// is follower
				commandBytes = "register_follow".getBytes("UTF-8");
				out.writeInt(commandBytes.length);
			}
			
			int newCounter = calculateCounter(counters.get(i));
			System.out.println("caculated counter: "+newCounter);
			counters.set(i, newCounter);
			byte[] challengeResponse = Integer.toString(counters.get(i)).getBytes("UTF-8");
			int cr = challengeResponse.length;
			out.writeInt(cr);
			byte[] msg = concatenate(challengeResponse, commandBytes);
			out.writeInt(msg.length);
			System.out.println("Signing Request with Client Private Key");
			byte[] msgSign = concatenate(msg, signature(msg));// creates
																												// MSG+SIG
			System.out.println("=============================================================");
			System.out.println("Request Sign: " + (new String(msgSign)));
			System.out.println("Ciphering signed request, using server public key");
			System.out.println("=============================================================");
			byte[] toSend = sessionEncrypt(sk, iv , msgSign);// Cipher
			System.out.println("Ciphered signed request: " + (new String(toSend)));
			out.writeInt(toSend.length);// Sends total length
			out.write(toSend);// Sends {MSG+SIG}serverpubkey
			System.out.println("Request Sent");
			
			
			
			byte[] wtsBytes = Integer.toString(wts).getBytes("UTF-8");

			counters.set(i, calculateCounter(counters.get(i)));
			challengeResponse = Integer.toString(counters.get(i)).getBytes("UTF-8");
			
			out.writeInt(challengeResponse.length);

			msg = concatenate(challengeResponse, wtsBytes);
			out.writeInt(msg.length);
			System.out.println("Signing Request with Client Private Key");

			msgSign = concatenate(msg, signature(msg));// creates

			toSend = sessionEncrypt(sk, iv, msgSign);

			out.writeInt(toSend.length);// Sends total length
			out.write(toSend);// Sends {MSG+SIG}serverpubkey

			
			s.getOutputStream().write(bb.array());
			s.getOutputStream().write(pubKey.getEncoded());
			s.getOutputStream().flush();

		}
	}

	public void save_password(byte[] domain, byte[] username, byte[] password) {
		try {
			wts++;
			SecretKey sk = sessionKeys.get(serverN);
			IvParameterSpec iv = ivs.get(serverN);
			DataOutputStream out = outs.get(serverN);

			System.out.println("=============================================================");
			System.out.println("Sending request to save password");
			out.flush();
			out.writeInt("put".getBytes("UTF-8").length);// Sends length of msg

			counters.set(serverN, calculateCounter(counters.get(serverN)));
			byte[] challengeResponse = Integer.toString(counters.get(serverN)).getBytes("UTF-8");
			int cr = challengeResponse.length;
			out.writeInt(cr);
			byte[] msg = concatenate(challengeResponse, "put".getBytes("UTF-8"));
			out.writeInt(msg.length);
			System.out.println("Signing Request with Client Private Key");
			byte[] msgSign = concatenate(msg, signature(msg));// creates

			System.out.println("=============================================================");
			System.out.println("Request Sign: " + (new String(msgSign)));
			System.out.println("Ciphering signed request, using server public key");
			System.out.println("=============================================================");
			byte[] toSend = sessionEncrypt(sk, iv, msgSign);// Cipher
			System.out.println("Ciphered signed request: " + (new String(toSend)));
			out.writeInt(toSend.length);// Sends total length
			out.write(toSend);// Sends {MSG+SIG}serverpubkey
			System.out.println("Request Sent");

			System.out.println("Sending domain: " + (new String(domain, "UTF-8")));
			out.flush();

			counters.set(serverN, calculateCounter(counters.get(serverN)));
			challengeResponse = Integer.toString(counters.get(serverN)).getBytes("UTF-8");
			cr = challengeResponse.length;
			out.writeInt(cr);
			msg = concatenate(challengeResponse, domain);
			out.writeInt(msg.length);
			System.out.println("Signing Request with Client Private Key");
			msgSign = concatenate(msg, signature(msg));// creates

			System.out.println("=============================================================");
			System.out.println("Domain Sign: " + (new String(msgSign)));
			System.out.println("Ciphering domain, using server public key");
			System.out.println("=============================================================");
			// toSend = encrypt(msgSign, getServerKey());// Cipher
			toSend = sessionEncrypt(sk, iv, msgSign);
			System.out.println("Ciphered signed domain: " + (new String(toSend)));
			out.writeInt(toSend.length);// Sends total length
			out.write(toSend);// Sends {MSG+SIG}serverpubkey
			System.out.println("Domain Sent");

			System.out.println("=============================================================");
			System.out.println("Sending username: " + (new String(username, "UTF-8")));
			out.flush();

			counters.set(serverN, calculateCounter(counters.get(serverN)));
			challengeResponse = Integer.toString(counters.get(serverN)).getBytes("UTF-8");
			cr = challengeResponse.length;
			out.writeInt(cr);
			msg = concatenate(challengeResponse, username);
			out.writeInt(msg.length);
			System.out.println("Signing Request with Client Private Key");
			msgSign = concatenate(msg, signature(msg));// creates

			System.out.println("=============================================================");
			System.out.println("Username Sign: " + (new String(msgSign)));
			System.out.println("Ciphering username, using server public key");
			System.out.println("=============================================================");
			// toSend = encrypt(msgSign, getServerKey());// Cipher
			toSend = sessionEncrypt(sk, iv, msgSign);
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

			byte[] wtsBytes = Integer.toString(wts).getBytes("UTF-8");

			counters.set(serverN, calculateCounter(counters.get(serverN)));
			challengeResponse = Integer.toString(counters.get(serverN)).getBytes("UTF-8");
			cr = challengeResponse.length;
			out.writeInt(cr);

			msg = concatenate(challengeResponse, wtsBytes);
			out.writeInt(msg.length);
			System.out.println("Signing Request with Client Private Key");

			msgSign = concatenate(msg, signature(msg));// creates

			toSend = sessionEncrypt(sk, iv, msgSign);

			out.writeInt(toSend.length);// Sends total length
			out.write(toSend);// Sends {MSG+SIG}serverpubkey

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void retrieve_password(byte[] domain, byte[] username) {
		byte[] inputByte = null;
		try {
			for (int i = 0; i < sessionKeys.size(); i++) {
				SecretKey sk = sessionKeys.get(i);
				IvParameterSpec iv = ivs.get(i);
				DataInputStream in = ins.get(i);
				DataOutputStream out = outs.get(i);

				System.out.println("=============================================================");
				System.out.println("Sending request to retrieve password");
				out.flush();
				out.writeInt("get".getBytes("UTF-8").length);// Sends length of
																// msg

				counters.set(i, calculateCounter(counters.get(i)));
				byte[] challengeResponse = Integer.toString(counters.get(i)).getBytes("UTF-8");
				int cr = challengeResponse.length;
				out.writeInt(cr);
				byte[] msg = concatenate(challengeResponse, "get".getBytes("UTF-8"));
				out.writeInt(msg.length);
				System.out.println("Signing Request with Client Private Key");
				byte[] msgSign = concatenate(msg, signature(msg));// creates

				System.out.println("=============================================================");
				System.out.println("Request Sign: " + (new String(msgSign)));
				System.out.println("Ciphering signed request, using server public key");
				System.out.println("=============================================================");
				byte[] toSend = sessionEncrypt(sk, iv, msgSign);// Cipher
				System.out.println("Ciphered signed request: " + (new String(toSend)));
				out.writeInt(toSend.length);// Sends total length
				out.write(toSend);// Sends {MSG+SIG}serverpubkey
				System.out.println("Request Sent");

				System.out.println("Sending domain: " + (new String(domain, "UTF-8")));
				out.flush();

				counters.set(i, calculateCounter(counters.get(i)));
				challengeResponse = Integer.toString(counters.get(i)).getBytes("UTF-8");
				cr = challengeResponse.length;
				out.writeInt(cr);
				msg = concatenate(challengeResponse, domain);
				out.writeInt(msg.length);
				System.out.println("Signing Request with Client Private Key");
				msgSign = concatenate(msg, signature(msg));// creates

				System.out.println("=============================================================");
				System.out.println("Domain Sign: " + (new String(msgSign)));
				System.out.println("Ciphering domain, using server public key");
				System.out.println("=============================================================");
				// toSend = encrypt(msgSign, getServerKey());// Cipher
				toSend = sessionEncrypt(sk, iv, msgSign);
				System.out.println("Ciphered signed domain: " + (new String(toSend)));
				out.writeInt(toSend.length);// Sends total length
				out.write(toSend);// Sends {MSG+SIG}serverpubkey
				System.out.println("Domain Sent");

				System.out.println("=============================================================");
				System.out.println("Sending username: " + (new String(username, "UTF-8")));
				out.flush();

				counters.set(i, calculateCounter(counters.get(i)));
				challengeResponse = Integer.toString(counters.get(i)).getBytes("UTF-8");
				cr = challengeResponse.length;
				out.writeInt(cr);
				msg = concatenate(challengeResponse, username);
				out.writeInt(msg.length);
				System.out.println("Signing Request with Client Private Key");
				msgSign = concatenate(msg, signature(msg));// creates

				System.out.println("=============================================================");
				System.out.println("Username Sign: " + (new String(msgSign)));
				System.out.println("Ciphering username, using server public key");
				System.out.println("=============================================================");
				// toSend = encrypt(msgSign, getServerKey());// Cipher
				toSend = sessionEncrypt(sk, iv, msgSign);
				System.out.println("Ciphered signed username: " + (new String(toSend)));
				out.writeInt(toSend.length);// Sends total length
				out.write(toSend);
				System.out.println("Username Sent");

				System.out.println("=============================================================");
				System.out.println("Receiving Password....");
				int passLength = in.readInt();
				int msgLength = in.readInt();

				byte[] inputAux = new byte[msgLength];
				byte[] decipherInput;
				in.readFully(inputAux, 0, msgLength);
				decipherInput = sessionDecrypt(sk, iv, inputAux);

				inputByte = Arrays.copyOfRange(decipherInput, 0, passLength);
				byte[] sig = Arrays.copyOfRange(decipherInput, passLength, passLength + 256);

				if (!verifySignature(sig, inputByte)) {
					System.out.println("Signature not verified, operation aborted");
					return;
				}

				receivedPasswords.add(new String(decrypt(inputByte, privKey)));
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		/*
		 * try { if (new String(inputByte, "UTF-8").equals("NULL")) {
		 * System.out.println("No password stored under this domain/username");
		 * } else { System.out.println("The password you requested: " + new
		 * String(decrypt(inputByte, privKey), "UTF-8")); } } catch
		 * (UnsupportedEncodingException e) { // TODO Auto-generated catch block
		 * e.printStackTrace(); }
		 */
	}

	public static Key getServerKey() {
		Key output = null;

		try {
			String pass = "pass";
			FileInputStream fis = new java.io.FileInputStream("ServerKeys");
			KeyStore sk = KeyStore.getInstance("JKS");
			// gets keystore if it already exists
			sk.load(fis, pass.toCharArray());

			Key serverPub = sk.getCertificate("ServerKeys").getPublicKey();

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
		}

		return output;
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

	public boolean verifySignature(byte[] sig, byte[] data) {
		boolean verifies = false;
		try {
			Signature rsaForVerify = Signature.getInstance("MD2withRSA");
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

	public int calculateCounter(int c) {
		c = c + 42;
		System.out.println("Challenge-Response new counter: " + c);
		return c;
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

}
