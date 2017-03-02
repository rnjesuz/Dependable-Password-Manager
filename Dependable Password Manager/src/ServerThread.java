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
    	 System.out.println("ESTOU AQUI");
    	try {
    	BufferedReader in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
        DataOutputStream out = new DataOutputStream(this.socket.getOutputStream());
        String clientSentence = in.readLine();
        String cap_Sentence = "Raceived:" +  clientSentence + '\n';
        System.out.println(cap_Sentence);
    	}
    	catch(Exception e){}
    }
            //implement your methods here

}