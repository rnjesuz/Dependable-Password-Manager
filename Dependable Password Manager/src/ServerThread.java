import java.io.*;
import java.net.Socket;
import java.security.*;

public class ServerThread extends Thread{

    private Socket socket = null;

    public ServerThread(Socket socket) {

        super("MiniServer");
        this.socket = socket;

    }

    public void run(){
            //Read input and process here
    	while(socket.isConnected()){

	    	try {
				BufferedReader in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
				String input = in.readLine();
				String[] inputParsed = input.split(" ", 0);
				System.out.println("input test: " + inputParsed[0]);
				String command = inputParsed[0];
				
				switch(command){
					case "register:":
						System.out.println(input);
						break;
						
					case "put:":
						System.out.println(input);
						break;
						
					case "get:":
						System.out.println(input);
						break;

					default:
						break;
					}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
    }
            //implement your methods here

    public void register(Key publicKey){
    	
    }
    
    public void put(Key publicKey, byte[] domain, byte[] username, byte[] password){
    	
    }
    
    public byte[] get(Key publicKey, byte[] domain, byte[] username){
    	//TODO change return to querried password
		return username;
    	
    }
}