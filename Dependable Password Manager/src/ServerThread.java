import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;

import javax.xml.bind.DatatypeConverter;

import java.nio.ByteBuffer;

import javax.crypto.*;

public class ServerThread extends Thread {

	private Socket socket = null;
	private String clientUsername = null;
	DataOutputStream out;

	public ServerThread(Socket socket) {

		super("MiniServer");
		this.socket = socket;

	}

	public void run() {
		// Read input and process here
		while (socket.isConnected()) {

			try {
				//BufferedReader in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
				//String input = in.readLine();
				out = new DataOutputStream(this.socket.getOutputStream());
				
				DataInputStream in = new DataInputStream(socket.getInputStream());
				byte[] inputByte = new byte[in.readInt()]; 
				in.readFully(inputByte, 0, inputByte.length);
				String input = new String (inputByte, "UTF-8");
				
				
				String[] inputParsed = input.split("#", 0);
				System.out.println("input test: " + inputParsed[0]);
				String command = inputParsed[0];

				switch (command) {
					case "username":
						clientUsername = inputParsed[1];

						break;

					case "register":
						System.out.println(input);
						clientUsername = inputParsed[1];
            			
            			register(receivePublicKey());

						break;

					case "put":
						System.out.println(input);

						put(getPublicKey(), inputParsed[1].getBytes(), inputParsed[2].getBytes(), inputParsed[3].getBytes());

						break;

					case "get":
						System.out.println(input);

						get(getPublicKey(), inputParsed[1].getBytes(), inputParsed[2].getBytes());
						break;

					default:
						break;
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	public void register(Key publicKey) {
		try {
			File file = new File(clientUsername);
			if (file.createNewFile()) {
			} else {
				System.out.println("User already registered");
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		String key = DatatypeConverter.printHexBinary(publicKey.getEncoded());
		FileOutputStream keyfos;
		try {
			keyfos = new FileOutputStream(clientUsername);
			keyfos.write(key.getBytes());
			keyfos.write('\n');		
			keyfos.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) {
		try {
			/*String _domain = new String(domain);
			String _username = new String(username);
			String _password = new String(password);
			List<String> lines = Arrays.asList(_domain + "|" + _username + "|" + _password +'\n');
			Path file = Paths.get(clientUsername);
			//Files.write(file, lines, Charset.forName("UTF-8"));
			Files.write(file, lines, StandardOpenOption.APPEND);*/
			String bar =""+ '|';
			String newLine = "" + '\n';
			//String _domain = new String(domain, "UTF-8");
			//String _username = new String(username, "UTF-8");
			Path file = Paths.get(clientUsername);
			Files.write(file, domain, StandardOpenOption.APPEND);
			Files.write(file, bar.getBytes(), StandardOpenOption.APPEND);
			Files.write(file, username, StandardOpenOption.APPEND);
			Files.write(file, bar.getBytes(), StandardOpenOption.APPEND);
			Files.write(file, password, StandardOpenOption.APPEND);
			Files.write(file, newLine.getBytes(), StandardOpenOption.APPEND);

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws Exception {
		byte[] output = null;
		
		for (String line : Files.readAllLines(Paths.get(clientUsername))) {
			String[] lineParsed = line.split("|", 0);

			String _domain = new String(domain, StandardCharsets.UTF_8);
			String _username = new String(username, StandardCharsets.UTF_8);
			/*if(Arrays.equals(lineParsed[0].getBytes(), _domain.getBytes()))
				if(Arrays.equals(lineParsed[1].getBytes(), _username.getBytes()))
					output = lineParsed[2].getBytes();*/
			if (lineParsed[0].equals(_domain))
				System.out.println("DEBUG 1");
				if (lineParsed[1].equals(_username))
					System.out.println("DEBUG 2");
					output = lineParsed[2].getBytes();
		}
		out.flush();
		out.write(output);
		return output;
	}


	public Key getPublicKey(){
		Key output = null;

		Scanner scan;
		try {
			scan = new Scanner(new File(clientUsername));
			scan.useDelimiter(Pattern.compile("\n"));
	    	String logicalLine = scan.next();

	    	output = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(DatatypeConverter.parseHexBinary(logicalLine)));
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
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

		byte[] lenb = new byte[4];
        try {
			socket.getInputStream().read(lenb,0,4);
			
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
}