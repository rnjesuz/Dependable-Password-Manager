import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import javax.crypto.*;

public class Client {

	public Client() {
	
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String sentence;
		Socket clientSocket = null;
		try {
			clientSocket = new Socket("localhost", 8080);
		} catch (UnknownHostException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		DataOutputStream out  = null;
		try {
			out = new DataOutputStream(clientSocket.getOutputStream());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        BufferedReader in = null;
		try {
			in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

        System.out.println("Ready");
        while(true) {
	        try {
	        sentence = System.console().readLine();
				out.writeBytes(sentence + '\n');
				
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        }
	}


	public void register(Key publicKey){
		
	}
	
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password){
			
	}
	
	public void get(Key publicKey, byte[] domain, byte[] username, byte[] password){
		
	}
}
