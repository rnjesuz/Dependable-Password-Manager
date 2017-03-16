import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Writer;
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
				int lenght = in.readInt();
				byte[] inputByte = new byte[lenght]; 
				in.readFully(inputByte, 0, inputByte.length);
				String input = new String (inputByte, "UTF-8");
				
				
				//String[] inputParsed = input.split("#", 0);
				//System.out.println("input test: " + inputParsed[0]);
				//String command = inputParsed[0];

				switch (input) {
					case "username":
						System.out.println(input);

						lenght = in.readInt();
						inputByte = new byte[lenght]; 
						in.readFully(inputByte, 0, inputByte.length);
						input = new String (inputByte, "UTF-8");
						System.out.println("CENASUser " + input);
						clientUsername = input;

						break;

					case "register":
						System.out.println(input);
						
						lenght = in.readInt();
						inputByte = new byte[lenght]; 
						in.readFully(inputByte, 0, inputByte.length);
						input = new String (inputByte, "UTF-8");
						System.out.println("CENASUser " + input);
						clientUsername = input;
            			
            			register(receivePublicKey());

						break;

					case "put":
						byte[] putDomain, putUsername, putPass;
						System.out.println(input);

						lenght = in.readInt();
						inputByte = new byte[lenght]; 
						in.readFully(inputByte, 0, inputByte.length);
						putDomain = inputByte;
						input = new String (inputByte, "UTF-8");
						System.out.println("CENAS" + input);
						
						lenght = in.readInt();
						inputByte = new byte[lenght]; 
						in.readFully(inputByte, 0, inputByte.length);
						putUsername = inputByte;
						input = new String (inputByte, "UTF-8");
						System.out.println("CENAS" + input);
						
						lenght = in.readInt();
						inputByte = new byte[lenght]; 
						in.readFully(inputByte, 0, inputByte.length);
						putPass = inputByte;
						
						put(getPublicKey(), putDomain, putUsername, putPass);

						break;

					case "get":
						byte[] getDomain, getUsername;
						System.out.println(input);

						lenght = in.readInt();
						inputByte = new byte[lenght]; 
						in.readFully(inputByte, 0, inputByte.length);
						getDomain = inputByte;
						input = new String (inputByte, "UTF-8");
						System.out.println("CENAS" + input);
						
						lenght = in.readInt();
						inputByte = new byte[lenght]; 
						in.readFully(inputByte, 0, inputByte.length);
						getUsername = inputByte;
						input = new String (inputByte, "UTF-8");
						System.out.println("CENAS" + input);

						get(getPublicKey(), getDomain, getUsername);
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
			String bar =""+ '#';
			String _domain = new String(domain, "UTF-8");
			String _username = new String(username, "UTF-8");
			String filename = _domain + bar + _username;
			
			FileOutputStream fos = new FileOutputStream(clientUsername + File.separator + filename);	
			fos.write(password);
			fos.close();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws Exception {
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
				byte[] output = new byte [fis.available()];
				fis.read(output);
				fis.close();
				
				out.flush();
				out.writeInt(output.length);
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


	public Key getPublicKey(){
		Key output = null;

		try {
			/*scan = new Scanner(new File(clientUsername));
			scan.useDelimiter(Pattern.compile("\n"));
	    	String logicalLine = scan.next();
	    	scan.close();*/

			BufferedReader brTest = new BufferedReader(new FileReader(clientUsername + File.separator + "publicKey"));
    		String text = brTest.readLine();
			// Stop. text is the first line.

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