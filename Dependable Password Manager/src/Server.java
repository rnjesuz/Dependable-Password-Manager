import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
	
	//id used to diferentiate diferent server proccsses
	private int ip;
	//ip used by the server to create a socket
	private int id;
	
	public Server(int _ip, int _id){
		//ip = _ip;
		//id = _id;
	}
	
	public static void main(String[] args) {
		ServerSocket serverSocket = null;

        boolean listeningSocket = true;
        try {
            serverSocket = new ServerSocket(Integer.parseInt(args[0]));
          System.out.println(serverSocket.getLocalPort());
        } catch (IOException e) {
            System.err.println("Could not listen on port");
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
