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
	
	public Client() {
		try {
			clientSocket = new Socket("localhost", 80);
			out = new DataOutputStream(this.clientSocket.getOutputStream());
		} catch (UnknownHostException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}

	public static void main(String[] args) throws IOException {
		// TODO Auto-generated method stub
        while(true) {
	        String command = System.console().readLine();
	        Client client = new Client();
	        switch (command) {
	        
			case "register":
			client.	Testregister();
				break;
				
			case "put":
			client.	Testput();
				break;
				
			case "get":
			client.	Testget();
				break;

			default:
				break;
			}
        }
	}


	public void Testregister() throws IOException{
		String TestpubKey="banana";
		
		out.writeBytes("register");
		out.writeBytes(TestpubKey);
	}
	
	public void Testput() throws IOException{
		String TestpubKey = "banana";
		String Testdomain = "url";
		String Testusername = "Cena";
		String Testpassword = "123";
		
		out.writeBytes("put");
		out.writeBytes(TestpubKey + Testdomain + Testusername + Testpassword);
	}
	
	public void Testget() throws IOException{
		String TestpubKey = "banana";
		String Testdomain = "url";
		String Testusername = "Cena";
		String Testpassword = "123";
		
		out.writeBytes("get");
		out.writeBytes(TestpubKey + Testdomain + Testusername + Testpassword);
	}
	
	public void register(Key publicKey){
		
	}
	
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password){
			
	}
	
	public void get(Key publicKey, byte[] domain, byte[] username, byte[] password){
		
	}
	
}
