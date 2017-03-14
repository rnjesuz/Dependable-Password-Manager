import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import javax.crypto.*;

public class Client {

	DataOutputStream out;
	Key pubKey;
	Key privKey;
	Socket clientSocket = null;
	
	public Client(String username, String password) {

		KeyStore ks = KeyStore.getInstance("JKS");
		init(ks, username, password);

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
		
		String username = System.console().reaLine();
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
		// TODO ECLIPSE VER EXCEPTION
		try {
			ks.getKey(username, password.toCharArray());
		} catch(Exception e) {
			ks.setEntry(username); //TODO REVER 
		}

	}
	
	public void register(Key publicKey){
		
	}
	
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password){
			
	}
	
	public void get(Key publicKey, byte[] domain, byte[] username, byte[] password){
		
	}
	
}
