import java.net.Socket;

public class ServerThread extends Thread{

    private Socket socket = null;

    public ServerThread(Socket socket) {

        super("MiniServer");
        this.socket = socket;

    }

    public void run(){
            //Read input and process here
    }
            //implement your methods here

}