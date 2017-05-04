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
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.UnknownHostException;
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
import java.util.ArrayList;
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
	SecretKey sessionKey;
	IvParameterSpec iv;
	private String clientUsername = "";
	static Key privKey;
	static Key pubKey;
	DataOutputStream out;
	DataInputStream in;
	int counter = 1 + (int) (Math.random() * 100000);
	int _port;
	byte[] lastPassSaved = null;
	ArrayList<SecretKey> sessionKeys = new ArrayList<SecretKey>();
	ArrayList<IvParameterSpec> ivs = new ArrayList<IvParameterSpec>();
	ArrayList<Integer> counters = new ArrayList<Integer>();

	ArrayList<Socket> sockets = new ArrayList<Socket>();
	ArrayList<DataOutputStream> outs = new ArrayList<DataOutputStream>();
	ArrayList<DataInputStream> ins = new ArrayList<DataInputStream>();

	// for (1,n) regular
	int wts = 0;
	int c_wts = 0;

	public ServerThread(Socket socket, int port) throws UnknownHostException, IOException {

		super("MiniServer");
		this.socket = socket;
		privKey = getServerKey("priv");
		pubKey = getServerKey("pub");
		_port = port;

	}

	public void run() {
		System.out.println("##################################################");
		System.out.println("NEW THREAD");
		System.out.println("##################################################");
		try {
			out = new DataOutputStream(this.socket.getOutputStream());

			in = new DataInputStream(socket.getInputStream());

			// ============================================================================================================================================
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
			
			byte[] putDomain, putUsername, putPass;
			int writeBack;
			int sigSize;
			
			ArrayList<byte[]> output;

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
			// ======================================================================================================================================
			// generating sessionKey
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			sessionKey = keyGen.generateKey();

			// build the initialization vector (randomly).
			SecureRandom random = new SecureRandom();
			byte ivaux[] = new byte[16];// generate random 16 byte IV AES is
			random.nextBytes(ivaux);// always 16bytes
			iv = new IvParameterSpec(ivaux);

			byte[] msgSign1 = encrypt(
					Base64.getDecoder().decode(Base64.getEncoder().encodeToString(sessionKey.getEncoded())), k);
			byte[] sig0 = signature(
					Base64.getDecoder().decode(Base64.getEncoder().encodeToString(sessionKey.getEncoded())));
			byte[] sigPart1 = encrypt(Arrays.copyOfRange(sig0, 0, (sig0.length / 2)), k);
			byte[] sigPart2 = encrypt(Arrays.copyOfRange(sig0, (sig0.length / 2), sig0.length), k);
			byte[] sessionCipher = concatenate(msgSign1, sigPart1);
			System.out.println("AHHHHHHHHHHHHHHH " + sessionCipher.length);
			out.writeInt(sessionCipher.length);
			out.writeInt(msgSign1.length);
			out.write(sessionCipher);
			out.flush();
			System.out.println("DEBUG: " + sigPart2.length);
			out.write(sigPart2);

			msgSign1 = encrypt(iv.getIV(), k);
			sig0 = signature(iv.getIV());
			sigPart1 = encrypt(Arrays.copyOfRange(sig0, 0, (sig0.length / 2)), k);
			sigPart2 = encrypt(Arrays.copyOfRange(sig0, (sig0.length / 2), sig0.length), k);
			sessionCipher = concatenate(msgSign1, sigPart1);
			out.writeInt(sessionCipher.length);
			out.writeInt(msgSign1.length);
			out.write(sessionCipher);
			out.flush();
			System.out.println("DEBUG: " + sigPart2.length);
			out.write(sigPart2);
			out.flush();
			// ==================================================================================================================================
			// sending counter
			out.writeInt(Integer.toString(counter).getBytes("UTF-8").length);
			byte[] msgSign = concatenate(Integer.toString(counter).getBytes("UTF-8"),
					signature(Integer.toString(counter).getBytes("UTF-8")));// creates
			// MSG+SIG
			byte[] toSend = sessionEncrypt(sessionKey, iv, msgSign);// Cipher
			out.writeInt(toSend.length);// Sends total length
			out.write(toSend);// Sends {MSG+SIG}serverpubkey
			System.out.println("Challenge Response send " + counter);

			// ============================================================================================================================================

			//connectServerServer(k);

			System.out.println("Ready For Commands");
			// =========================================================================
			while (socket.isConnected()) {
				
				// preparing variables for command requests
				//msgLenght = in.readInt();
				crLength = in.readInt();
				int msgCrLength = in.readInt();
				lenght = in.readInt();
				System.out.println(lenght);
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
					System.out.println("proposed counter: "+proposedCounter);
					System.out.println("calculated counter: "+calculateCounter());
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

				input = new String(msg, "UTF-8");

				switch (input) {

				case "martelo":
					connectServerServer(k);
					break;
					
				case "register":

					System.out.println("switch case register");
					output = msgRefactor(counter, sessionKey, iv, k, in);
					counter = Integer.parseInt(new String(output.get(3), "UTF-8"));

					System.out.println("################################################");
					System.out.println("RECEIVED MSG:");
					System.out.println(new String(output.get(2), "UTF-8"));
					System.out.println("================================================");
					System.out.println("DECRYPTED MSG:");
					System.out.println(new String(output.get(0), "UTF-8"));
					System.out.println("================================================");
					System.out.println("SIGNATURE:");
					System.out.println(new String(output.get(1), "UTF-8"));
					System.out.println("################################################");
					System.out.println("");

					counterBytes = output.get(0);

					// for 1,n regular
					c_wts = Integer.parseInt(new String(counterBytes, "UTF-8"));
					if (c_wts > wts) {
						register(receivePublicKey(), output.get(1));
						wts = c_wts;
					} else
						System.out.println("error in wts");

					//ask followers for what they wrote
					
					try {
						System.out.println("estou a espera");
						sleep(5000);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
					askRegisterCommand(output.get(1));

					break;

				case "register_follow":
					System.out.println("switch case register follow");
					output = msgRefactor(counter, sessionKey, iv, k, in);
					counter = Integer.parseInt(new String(output.get(3), "UTF-8"));

					System.out.println("################################################");
					System.out.println("RECEIVED MSG:");
					System.out.println(new String(output.get(2), "UTF-8"));
					System.out.println("================================================");
					System.out.println("DECRYPTED MSG:");
					System.out.println(new String(output.get(0), "UTF-8"));
					System.out.println("================================================");
					System.out.println("SIGNATURE:");
					System.out.println(new String(output.get(1), "UTF-8"));
					System.out.println("################################################");
					System.out.println("");

					counterBytes = output.get(0);
					
					// for 1,n regular
					c_wts = Integer.parseInt(new String(counterBytes, "UTF-8"));
					if (c_wts > wts) {
						register(receivePublicKey(), output.get(1));
						wts = c_wts;
					} else {
						System.out.println("error in wts");
					}
					
					break;
					
				case "register_to_leader":
					System.out.println("Follower Sending register value to leader");
					sigSize = in.readInt();
					
					counter = sendRefactor(getPublicKey(sigSize).getEncoded(), counter, sessionKey, iv, out);
					System.out.println("sent saved key to leader");
					
					System.out.println("waiting response from leader");
					
					output = msgRefactor(counter, sessionKey, iv, pubKey, in);
					counter = Integer.parseInt(new String (output.get(3)));
					
					if("NOACK".equals(new String(output.get(0), "UTF-8"))) {
						break;
					} else {
						System.out.println("ACK received check if different");
						
						String leader = DatatypeConverter.printHexBinary(output.get(0));
						String follower  = DatatypeConverter.printHexBinary(getPublicKey(sigSize).getEncoded());
						
						System.out.println("LEADER: " + leader);
						System.out.println("FOLLOWER: " + follower);
						
						if(!Arrays.equals(output.get(0), getPublicKey(sigSize).getEncoded())) {
							System.out.println("Overwrite");
							
							X509EncodedKeySpec ks = new X509EncodedKeySpec(output.get(0));

							KeyFactory kf = KeyFactory.getInstance("RSA");
							PublicKey key = kf.generatePublic(ks);
							
							register(key, getClientSig(sigSize));
							System.out.println("Overwrite DONE");
						}
						
						counter = sendRefactor("ACK".getBytes("UTF-8"), counter, sessionKey, iv, out);
					}
					
					break;
					
				case "put":
					
					try {
						System.out.println("estou a espera");
						sleep(5000);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

					output = msgRefactor(counter, sessionKey, iv, k, in);
					counter = Integer.parseInt(new String(output.get(3), "UTF-8"));
					putDomain = output.get(0);
					// input = new String(msg, "UTF-8");

					System.out.println("################################################");
					System.out.println("RECEIVED MSG:");
					System.out.println(new String(output.get(2), "UTF-8"));
					System.out.println("================================================");
					System.out.println("DECRYPTED MSG:");
					System.out.println(new String(output.get(0), "UTF-8"));
					System.out.println("================================================");
					System.out.println("SIGNATURE:");
					System.out.println(new String(output.get(1), "UTF-8"));
					System.out.println("################################################");
					System.out.println("");

					output = msgRefactor(counter, sessionKey, iv, k, in);
					counter = Integer.parseInt(new String(output.get(3), "UTF-8"));
					putUsername = output.get(0);

					System.out.println("################################################");
					System.out.println("RECEIVED MSG:");
					System.out.println(new String(output.get(2), "UTF-8"));
					System.out.println("================================================");
					System.out.println("DECRYPTED MSG:");
					System.out.println(new String(output.get(0), "UTF-8"));
					System.out.println("================================================");
					System.out.println("SIGNATURE:");
					System.out.println(new String(output.get(1), "UTF-8"));
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

					output = msgRefactor(counter, sessionKey, iv, k, in);
					counter = Integer.parseInt(new String(output.get(3), "UTF-8"));
					sig = output.get(1);
					counterBytes = output.get(0);

					// for 1,n regular
					c_wts = Integer.parseInt(new String(counterBytes, "UTF-8"));
					String name = null;
					if (c_wts > wts) {
						name = put(getPublicKey(sig.length), putDomain, putUsername, putPass, sig);
						wts = c_wts;
					} else
						System.out.println("error in wts");

					
					askPutCommand(putDomain, putUsername, putPass, output.get(1));
					//writeBack and send write back to followers

					break;

				case "put_follow":

					output = msgRefactor(counter, sessionKey, iv, k, in);
					counter = Integer.parseInt(new String(output.get(3), "UTF-8"));
					putDomain = output.get(0);
					// input = new String(msg, "UTF-8");

					System.out.println("################################################");
					System.out.println("RECEIVED MSG:");
					System.out.println(new String(output.get(2), "UTF-8"));
					System.out.println("================================================");
					System.out.println("DECRYPTED MSG:");
					System.out.println(new String(output.get(0), "UTF-8"));
					System.out.println("================================================");
					System.out.println("SIGNATURE:");
					System.out.println(new String(output.get(1), "UTF-8"));
					System.out.println("################################################");
					System.out.println("");

					output = msgRefactor(counter, sessionKey, iv, k, in);
					counter = Integer.parseInt(new String(output.get(3), "UTF-8"));
					putUsername = output.get(0);

					System.out.println("################################################");
					System.out.println("RECEIVED MSG:");
					System.out.println(new String(output.get(2), "UTF-8"));
					System.out.println("================================================");
					System.out.println("DECRYPTED MSG:");
					System.out.println(new String(output.get(0), "UTF-8"));
					System.out.println("================================================");
					System.out.println("SIGNATURE:");
					System.out.println(new String(output.get(1), "UTF-8"));
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

					output = msgRefactor(counter, sessionKey, iv, k, in);
					counter = Integer.parseInt(new String(output.get(3), "UTF-8"));
					sig = output.get(1);
					counterBytes = output.get(0);

					// for 1,n regular
					c_wts = Integer.parseInt(new String(counterBytes, "UTF-8"));
					String fileName = null;
					if (c_wts > wts) {
						fileName = put(getPublicKey(sig.length), putDomain, putUsername, putPass, sig);
						wts = c_wts;
					} else
						System.out.println("error in wts");

					break;
					
				case "put_to_leader":
					sigSize = in.readInt();
					
					System.out.println("receiving domain from leader");
					output = msgRefactor(counter, sessionKey, iv, pubKey, in);
					counter = Integer.parseInt(new String(output.get(3), "UTF-8"));
					byte[] domain = output.get(0);
					
					System.out.println("receiving username from leader");
					output = msgRefactor(counter, sessionKey, iv, pubKey, in);
					counter = Integer.parseInt(new String(output.get(3), "UTF-8"));
					byte[] username = output.get(0);
					
					System.out.println("Sending pass to leader");
					
					output = get((Key)pubKey, domain, username, sigSize);
					byte[] pass = output.get(0);
					
					counter = calculateCounterServer(counter);
					counterBytes = Integer.toString(counter).getBytes("UTF-8");
					
					msg = concatenate(counterBytes, output.get(0));//creates cr+Pass
					msgSign = concatenate(msg, signature(msg));// creates MSG+SIG
					toSend = sessionEncrypt(sessionKey, iv , msgSign);// Cipher
					
					out.writeInt(counterBytes.length);//size of cr
					out.writeInt(msg.length);//size of msg+sig
					out.writeInt(toSend.length);// Sends total length
					
					out.write(toSend);// Sends {MSG+SIG}serverpubkey
				
					System.out.println("Pass sent to leader");
					
					//WAIT FOR LEADER RESPONSE
					System.out.println("Waiting for leader response");
					output = msgRefactor(counter, sessionKey, iv, pubKey, in);
					counter = Integer.parseInt(new String(output.get(3), "UTF-8"));
					
					if("NOACK".equals(new String(output.get(0), "UTF-8"))) {
						System.out.println("Writeback");
						break;
					} else {
						if(!Arrays.equals(pass, output.get(0))) {
							System.out.println("Overwrite");
							put(getPublicKey(output.get(1).length), domain, username, output.get(0), output.get(1));
						}
						
						counter = sendRefactor("ACK".getBytes("UTF-8"), counter, sessionKey, iv, out);
						
					}
					
					break;
					
				case "get":
					byte[] getDomain, getUsername;

					output = msgRefactor(counter, sessionKey, iv, k, in);
					counter = Integer.parseInt(new String(output.get(3), "UTF-8"));
					getDomain = output.get(0);

					System.out.println("################################################");
					System.out.println("RECEIVED MSG:");
					System.out.println(new String(output.get(2), "UTF-8"));
					System.out.println("================================================");
					System.out.println("DECRYPTED MSG:");
					System.out.println(new String(output.get(0), "UTF-8"));
					System.out.println("================================================");
					System.out.println("SIGNATURE:");
					System.out.println(new String(output.get(1), "UTF-8"));
					System.out.println("################################################");
					System.out.println("");

					output = msgRefactor(counter, sessionKey, iv, k, in);
					counter = Integer.parseInt(new String(output.get(3), "UTF-8"));
					getUsername = output.get(0);

					System.out.println("################################################");
					System.out.println("RECEIVED MSG:");
					System.out.println(new String(output.get(2), "UTF-8"));
					System.out.println("================================================");
					System.out.println("DECRYPTED MSG:");
					System.out.println(new String(output.get(0), "UTF-8"));
					System.out.println("================================================");
					System.out.println("SIGNATURE:");
					System.out.println(new String(output.get(1), "UTF-8"));
					System.out.println("################################################");
					System.out.println("");

					output = get(getPublicKey(output.get(1).length), getDomain, getUsername, output.get(1).length);
					
					out.writeInt(output.get(0).length);
					out.writeInt(output.get(2).length);
					out.write(output.get(2));

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

	private void askPutCommand(byte[] domain, byte[] username, byte[] password, byte[] sigClient) throws IOException {
		System.out.println("putcommand");
		ArrayList<byte[]> values = new ArrayList<byte[]>();
		ArrayList<byte[]> output = new ArrayList<byte[]>();
		
		int acks = 0, newCounter = 0, actualizedCounter=0;
		byte[] msg = null,  msgSign = null, 
				toSend = null, challengeResponse = null, commandBytes = null;
		
		values.add(password);
		
		for (int i = 0; i < sessionKeys.size(); i++) {
			SecretKey sk = sessionKeys.get(i);
			IvParameterSpec iv = ivs.get(i);
			DataOutputStream out = outs.get(i);
			DataInputStream in = ins.get(i);

			out.flush();
			
			//REQUEST FOllOWER TO EXECUTE put_to_leader
			
			actualizedCounter = sendRefactor("put_to_leader".getBytes("UTF-8"), counters.get(i), sk, iv, out);
			counters.set(i, actualizedCounter);
			
			//in put_to_leader
			out.writeInt(sigClient.length);//sends size of client signature to follower
			
			System.out.println("Sending domain to follower");
			
			
			actualizedCounter = sendRefactor(domain, counters.get(i), sk, iv, out);
			counters.set(i, actualizedCounter);
			
			
			System.out.println("Sent domain to Follower");
			
			System.out.println("Sending username to follower");
			
			actualizedCounter = sendRefactor(username, counters.get(i), sk, iv, out);
			counters.set(i, actualizedCounter);
			
			
			System.out.println("Sent username to Follower");
			
			System.out.println("Waiting for follower response");
			output = msgRefactor(counters.get(i), sk, iv, pubKey, in);
			counters.set(i, Integer.parseInt(new String(output.get(3), "UTF-8")));
			System.out.println("Received follower response");
			
			values.add(output.get(0));	
			
			System.out.println("next!!!");
		}
		
		//CHECKS THE MAJORITY ELEMENT
		System.out.println("Checking for majority element");
		int count = 0;
		String majorityElement = null;
	    for (int i = 0; i < values.size(); i++) {
	    	String aux = new String(values.get(i),"UTF-8");
	        if (count == 0)
	            majorityElement = aux;
	        if (aux.equals(majorityElement)) 
	            count++;
	        else
	            count--;
	    }
	    count = 0;
	    for (int i = 0; i < values.size(); i++) {
	    	String aux = new String(values.get(i),"UTF-8");
	        if (aux.equals(majorityElement))
	            count++;
	    }
	    boolean sendAck = true;
	    if (!(count > values.size()/2)) {
	    	sendAck = false;
	    	System.out.println("No consensus reached");
	    	return;
	    }		
	    
	    if(!Arrays.equals(majorityElement.getBytes("UTF-8"), password)) {
			System.out.println("Leader Overwrite");
			put(getPublicKey(sigClient.length), domain, username, majorityElement.getBytes("UTF-8"), sigClient);
		}
	    
		for (int i = 0; i < sessionKeys.size(); i++) {
			SecretKey sk = sessionKeys.get(i);
			IvParameterSpec iv = ivs.get(i);
			DataOutputStream out = outs.get(i);
			DataInputStream in = ins.get(i);
			
			if(sendAck) {
				System.out.println("Consensus is: " + majorityElement);
				
				System.out.println("Sending pass to followers");
				
				actualizedCounter = sendRefactor(username, counters.get(i), sk, iv, out);
				counters.set(i, actualizedCounter);
				
				System.out.println("Sent pass to write to Followers");
				
				System.out.println("Waiting for follower response");
				output = msgRefactor(counters.get(i), sk, iv, pubKey, in);
				counters.set(i, Integer.parseInt(new String(output.get(3), "UTF-8")));
				System.out.println("Received follower response");
				
				if((new String(output.get(0), "UTF-8").equals("ACK"))) {
					acks++;
				}
				
			} else {
				//SEND WRITEBACK TO FOLLOWERS
				newCounter = calculateCounterServer(counters.get(i));
				counters.set(i, newCounter);
				challengeResponse = Integer.toString(counters.get(i)).getBytes("UTF-8");
				msg = concatenate(challengeResponse, "NOACK".getBytes("UTF-8"));//challengeResponse + domain
				msgSign = concatenate(msg, signature(msg));// creates MSG+SIG
				toSend = sessionEncrypt(sk, iv , msgSign);// Cipher
				
				out.writeInt(challengeResponse.length);//sends length of cr
				out.writeInt(msg.length);//sends length of cr+msg
				out.writeInt(toSend.length);// Sends total length
				
				out.write(toSend);// Sends {MSG+SIG}serverpubkey
			}			
		}
		
		//(n+f)/2 
		if(acks >= 4)
			sendACK(true);
		else sendACK(false);
		
	}

	private void askRegisterCommand(byte[] sigClient) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		
		System.out.println("registercommand");
		ArrayList<byte[]> values = new ArrayList<byte[]>();		
		int lenght, msgLenght, acks = 0;
		byte[] msg, sig, msgSign, toSend, inputByte = null;
		
		values.add(getPublicKey(sigClient.length).getEncoded());
		
		
		for (int i = 0; i < sessionKeys.size(); i++) {
			SecretKey sk = sessionKeys.get(i);
			IvParameterSpec iv = ivs.get(i);
			DataOutputStream out = outs.get(i);
			DataInputStream in = ins.get(i);
			int crCounter =  counters.get(i);
			int actualizedCounter;
			out.flush();
			
			byte[] commandBytes;
			commandBytes = "register_to_leader".getBytes("UTF-8");

			actualizedCounter = sendRefactor(commandBytes, crCounter, sk, iv, out);
			counters.set(i, actualizedCounter);
			
			out.writeInt(sigClient.length);//sends size of client signature to follower
			
			ArrayList<byte[]> output = msgRefactor(counters.get(i), sk, iv, pubKey,  in);
			counters.set(i, Integer.parseInt(new String (output.get(3))));
			
			values.add(output.get(0));			
		}
		
		//CHECKS THE MAJORITY ELEMENT
		int count = 0;
		byte[] majorityElement = null;
	    for (int i = 0; i < values.size(); i++) {
	        if (count == 0)
	            majorityElement = values.get(i);
	        if (Arrays.equals(values.get(i),majorityElement)) 
	            count++;
	        else
	            count--;
	    }
	    count = 0;
	    for (int i = 0; i < values.size(); i++) {
	        if (Arrays.equals(values.get(i),majorityElement))
	            count++;
	    }
	    boolean sendAck = true;
	    if (!(count > values.size()/2)) {
	    	sendAck = false;
	    }		
	    
		for (int i = 0; i < sessionKeys.size(); i++) {
			SecretKey sk = sessionKeys.get(i);
			IvParameterSpec iv = ivs.get(i);
			DataOutputStream out = outs.get(i);
			DataInputStream in = ins.get(i);
			int actualizedCounter;
			int crCounter = counters.get(i);
			
			if(sendAck) {
				
				System.out.println("Send Ack to " + i);
				
				actualizedCounter = sendRefactor(majorityElement, crCounter, sk, iv, out);
				counters.set(i, actualizedCounter);
				
				System.out.println("Receiving ack from " + i);
				//waiting for ACK from followers
				ArrayList<byte[]> output = msgRefactor(counters.get(i), sk, iv, pubKey, in);
				counters.set(i, Integer.parseInt(new String (output.get(3))));
				
				if((new String(output.get(0), "UTF-8").equals("ACK"))) {
					acks++;
				}
				
			} else {
				msg = "NOACK".getBytes("UTF-8");
				sig = signature(msg);
				msgSign = concatenate(msg, sig);
				toSend = sessionEncrypt(sk, iv, msgSign);
			}			
		}
		
		//(n+f)/2 
		if(acks >= 4) {
			sendACK(true);
			if(Arrays.equals(majorityElement, getPublicKey(sigClient.length).getEncoded())) {
				System.out.println("Overwrite");
				
				X509EncodedKeySpec ks = new X509EncodedKeySpec(majorityElement);

				KeyFactory kf = KeyFactory.getInstance("RSA");
				PublicKey key = kf.generatePublic(ks);
				
				register(key, sigClient);
				System.out.println("Overwrite DONE");
			}
		}
		else sendACK(false);
	}

	private void connectServerServer(Key k) throws UnknownHostException, IOException {

			for (int i = 8080; i <= 8084; i++) {
				if (i != _port) {
					sockets.add(new Socket("localhost", i));
					System.out.println(_port + "    :    " + i);
				}
			}
			System.out.println(sockets.size());
			for (Socket s : sockets) {
				outs.add(new DataOutputStream(s.getOutputStream()));
				ins.add(new DataInputStream(s.getInputStream()));
			}
			System.out.println(outs.size());
			System.out.println(ins.size());

			sendUsername();
			challengeResponse();
			System.out.println("tamanhoooo: "+sockets.size());
			
	}
	
	private void sendTag() throws IOException{
		for (int i = 0; i < sockets.size(); i++) {
			DataOutputStream out = outs.get(i);
			SecretKey sk = sessionKeys.get(i);
			IvParameterSpec iv = ivs.get(i);
	
			byte[] msg = "follower".getBytes("UTF-8");
			System.out.println(new String(msg, "UTF-8"));
			
			counters.set(i, calculateCounterServer(counters.get(i)));
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
			out.writeInt(1);
		}
	}

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

		byte[] msgSign1 = encrypt(clientUsername.getBytes("UTF-8"), pubKey);
		byte[] sig0 = signature(clientUsername.getBytes("UTF-8"));
		byte[] sigPart1 = encrypt(Arrays.copyOfRange(sig0, 0, (sig0.length / 2)), pubKey);
		byte[] sigPart2 = encrypt(Arrays.copyOfRange(sig0, (sig0.length / 2), sig0.length), pubKey);
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
		;
		for (DataInputStream in : ins) {
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

			if (!verifySignature(pubKey, sig, msg)) {
				System.out.println("Signature not verified, username not registered");
				for (DataOutputStream out : outs) {
					out.close();
				}

				for (DataInputStream inn : ins) {
					inn.close();
				}

				return;
			}
			SecretKey sessionKey = new SecretKeySpec(msg, 0, 16, "AES");
			sessionKeys.add(sessionKey);
		}
		
		for (DataInputStream in : ins) {
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

			if (!verifySignature(pubKey, sig, msg)) {
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
	}
	
	public void challengeResponse() throws IOException {

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

			if (!verifySignature(pubKey, sig, msg)) {
				System.out.println("Signature not verified, no action taken");
				return;
			}
			counters.add(Integer.parseInt(new String(msg, "UTF-8")));
			System.out.println("CHALLENGE RESPONSE in LIST: " + counters.get(i));
		}

	}
	
	public int calculateCounterServer(int c) {
		c = c + 42;
		System.out.println("Challenge-Response Server new counter: " + c);
		return c;
	}
	
	public ArrayList<byte[]> msgRefactor(int challengeResponse, SecretKey sessionKey, IvParameterSpec iv, Key k, DataInputStream in) throws IOException {
		int crLength = in.readInt();
		int msgCrLength = in.readInt();
		int lenght = in.readInt();
		byte[] inputByte = new byte[lenght];
		in.readFully(inputByte, 0, lenght);
		byte[] decipherInput = sessionDecrypt(sessionKey, iv, inputByte);
		byte[] msg = Arrays.copyOfRange(decipherInput, 0, msgCrLength);
		byte[] sig = Arrays.copyOfRange(decipherInput, msgCrLength, decipherInput.length);

		if (!verifySignature(k, sig, msg)) {
			System.out.println("Signature not verified, no action taken");
			return null;
		}

		byte[] counterBytes = Arrays.copyOfRange(msg, 0, crLength);
		msg = Arrays.copyOfRange(msg, crLength, msgCrLength);
		int proposedCounter = Integer.parseInt(new String(counterBytes, "UTF-8"));
		
		System.out.println(proposedCounter +  "          :           "  + calculateCounterServer(challengeResponse) );

		if (proposedCounter != calculateCounterServer(challengeResponse)) {
			System.out.println("Challenge Response failed");
			return null;
		}

		ArrayList<byte[]> output = new ArrayList<byte[]>();
		output.add(msg);
		output.add(sig);
		output.add(inputByte);
		output.add(counterBytes);

		return output;
	}
	
	public int sendRefactor(byte[] msg, int counter, SecretKey sk, IvParameterSpec iv, DataOutputStream out){
		int newCounter = 0;
		try {
			newCounter= calculateCounterServer(counter);
			byte[]  challengeResponse = Integer.toString(newCounter).getBytes("UTF-8");
			int cr = challengeResponse.length;
			out.writeInt(cr);
			msg = concatenate(challengeResponse, msg);
			out.writeInt(msg.length);
			byte[]msgSign = concatenate(msg, signature(msg));// creates MSG+SIG
			byte[]toSend = sessionEncrypt(sk, iv , msgSign);// Cipher
			out.writeInt(toSend.length);// Sends total length
			out.write(toSend);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return newCounter;
	}

	public void writeBack(String name) {

		try {
			if (lastPassSaved == null) {
				File f = new File(name);
				f.delete();
			} else {
				FileOutputStream fos = new FileOutputStream(
						Integer.toString(_port) + File.separator + clientUsername + File.separator + name);
				fos.write(lastPassSaved);
				fos.close();
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public void register(Key publicKey, byte[] signature) {
		
		File dir = new File(Integer.toString(_port) + File.separator + clientUsername);
		if (dir.mkdir()) {
		} else {
			System.out.println("User already registered");
		}

		String key = DatatypeConverter.printHexBinary(publicKey.getEncoded());
		FileOutputStream keyfos;
		try {
			keyfos = new FileOutputStream(Integer.toString(_port) + File.separator + clientUsername + File.separator + "publicKey");
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

	public String put(Key publicKey, byte[] domain, byte[] username, byte[] password, byte[] signature) {
		try {

			StringBuilder hexString = new StringBuilder();
			for (int i = 0; i < domain.length; i++) {
				String hex = Integer.toHexString(0xFF & domain[i]);
				if (hex.length() == 1)
					hexString.append('0');

				hexString.append(hex);
			}

			for (int i = 0; i < username.length; i++) {
				String hex = Integer.toHexString(0xFF & domain[i]);
				if (hex.length() == 1)
					hexString.append('0');

				hexString.append(hex);
			}

			String filename = hexString.toString().toUpperCase();
			File f = new File(filename);
			if (f.exists() && !f.isDirectory()) {
				FileInputStream fis = new FileInputStream(f);
				lastPassSaved = new byte[fis.available()];
				fis.read(lastPassSaved);
				fis.close();
			}

			FileOutputStream fos = new FileOutputStream(
					Integer.toString(_port) + File.separator + clientUsername + File.separator + filename);

			System.out.println("################################################");
			System.out.println("Saving password with code of client " + clientUsername);
			System.out.println("PASS:");
			System.out.println(new String(password, "UTF-8"));
			System.out.println("################################################");
			System.out.println("");

			fos.write(password);
			fos.write(signature);
			fos.close();
			return filename;

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public ArrayList<byte[]> get(Key publicKey, byte[] domain, byte[] username, int sigSize) throws Exception {
		ArrayList<byte[]> output = new ArrayList<byte[]>();

		StringBuilder hexString = new StringBuilder();
		for (int i = 0; i < domain.length; i++) {
			String hex = Integer.toHexString(0xFF & domain[i]);
			if (hex.length() == 1)
				hexString.append('0');

			hexString.append(hex);
		}

		for (int i = 0; i < username.length; i++) {
			String hex = Integer.toHexString(0xFF & domain[i]);
			if (hex.length() == 1)
				hexString.append('0');

			hexString.append(hex);
		}

		String filename = hexString.toString().toUpperCase();

		File file = new File(Integer.toString(_port) + File.separator + clientUsername + File.separator + filename);
		File dir = new File(Integer.toString(_port) + File.separator + clientUsername);
		for (File f : dir.listFiles()) {
			if (f.getName().equalsIgnoreCase(filename)) {
				FileInputStream fis = new FileInputStream(file);
				byte[] pass = new byte[fis.available() - sigSize];
				fis.read(pass);
				fis.close();

				byte[] sig = signature(pass);
				byte[] toSend = sessionEncrypt(sessionKey, iv, concatenate(pass, sig));
				output.add(pass);
				output.add(sig);
				output.add(toSend);
				/*
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
				*/
				return output;
			}
		}

		System.out.println("No password stored under this domain/username");
		return null;
	}

	public Key getPublicKey(int sigSize) {
		Key output = null;

		try {
			/*
			 * scan = new Scanner(new File(clientUsername));
			 * scan.useDelimiter(Pattern.compile("\n")); String logicalLine =
			 * scan.next(); scan.close();
			 */

			File file = new File(
					Integer.toString(_port) + File.separator + clientUsername + File.separator + "publicKey");
			FileInputStream fis = new FileInputStream(file);
			byte[] outputbytes = new byte[fis.available() - sigSize];
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
	
	public byte[] getClientSig(int sigSize) {

		byte[] outputbytes =null;
		byte[] output = null;
		
		try {
			
			File file = new File(
					Integer.toString(_port) + File.separator + clientUsername + File.separator + "publicKey");
			FileInputStream fis = new FileInputStream(file);
			int fileSize = fis.available();
			outputbytes = new byte[fileSize];
			
			System.out.println("Sig size: " + sigSize);
			System.out.println("file size: " + fileSize);
			
			fis.read(outputbytes);
			
			output = Arrays.copyOfRange(outputbytes, fileSize-sigSize, fileSize);

			System.out.println("CLIENT SIG: " + output);

			fis.close();
			
		} catch (FileNotFoundException e) {
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

	public int calculateCounter() {
		System.out.println("NEW COUNTER: " + (counter + 42));

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

	public void sendACK(boolean ack) throws IOException {
		byte[] ackBytes = null;
		
		if(ack)
			ackBytes = "ACK".getBytes("UTF-8");			
		else ackBytes = "NOACK".getBytes("UTF-8");
		
		byte[] wtsBytes = Integer.toString(wts).getBytes("UTF-8");
		byte[] msgWtsBytes = concatenate(wtsBytes, ackBytes);
		out.writeInt(wtsBytes.length);
		out.writeInt(msgWtsBytes.length);
		byte[] msgSigned = concatenate(msgWtsBytes, signature(msgWtsBytes));
		byte[] toSendBytes = sessionEncrypt(sessionKey, iv, msgSigned);
		out.writeInt(toSendBytes.length);
		out.write(toSendBytes);
	}
}