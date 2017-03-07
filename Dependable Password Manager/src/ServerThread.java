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
    	while(socket.isConnected()){

	    	try {
				BufferedReader in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
				String outcenas = in.readLine();
				String[] array = outcenas.split(" ", 0);
				System.out.println("input test: " + array[0]);

				switch(array[0]){
					case "register:":
						System.out.println(outcenas);
						break;
						
					case "put:":
						System.out.println(outcenas);
						break;
						
					case "get:":
						System.out.println(outcenas);
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

}