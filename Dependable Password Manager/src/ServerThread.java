import java.io.*;
import java.net.Socket;

public class ServerThread extends Thread{

    private Socket socket = null;

    public ServerThread(Socket socket) {

        super("MiniServer");
        this.socket = socket;

    }

    public void run(){
            //Read input and process here
    	try {
			BufferedReader in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
			switch(in.readLine()) {
			case "register":
				System.out.println("register" + in.readLine());
				break;
				
			case "put":
				System.out.println("put" + in.readLine());
				break;
				
			case "get":
				System.out.println("get" + in.readLine());
				break;

			default:
				break;
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
            //implement your methods here

}