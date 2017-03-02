import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
/*import java.security.*;
import javax.crypto.*;*/

public class Server {

	public static void main(String[] args) {
		ServerSocket serverSocket = null;

        boolean listeningSocket = true;
        try {
            serverSocket = new ServerSocket(80);
        } catch (IOException e) {
            System.err.println("Could not listen on port: 2343");
        }

        while(listeningSocket){
            Socket clientSocket = null;
			try {
				clientSocket = serverSocket.accept();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
            ServerThread thread = new ServerThread(clientSocket);
            thread.start();
        }
        try {
			serverSocket.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
