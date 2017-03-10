import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.util.Arrays;
import java.util.List;

public class ServerThread extends Thread {

	private Socket socket = null;

	public ServerThread(Socket socket) {

		super("MiniServer");
		this.socket = socket;

	}

	public void run() {
		// Read input and process here
		while (socket.isConnected()) {

			try {
				BufferedReader in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
				String input = in.readLine();
				String[] inputParsed = input.split(" ", 0);
				System.out.println("input test: " + inputParsed[0]);
				String command = inputParsed[0];

				switch (command) {
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
	// implement your methods here

	public void register(Key publicKey) {
		try {
			File file = new File(publicKey.toString() + ".txt");
			if (file.createNewFile()) {
			} else {
				System.out.println("User already registered");
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) {
		try {
			String _domain = new String(domain, StandardCharsets.UTF_8);
			String _username = new String(username, StandardCharsets.UTF_8);
			String _password = new String(password, StandardCharsets.UTF_8);
			List<String> lines = Arrays
					.asList(_domain.toString() + "|" + _username.toString() + "|" + _password.toString());
			Path file = Paths.get(publicKey.toString() + ".txt");
			Files.write(file, lines, Charset.forName("UTF-8"));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws Exception {
		byte[] output = null;
		
		for (String line : Files.readAllLines(Paths.get(publicKey.toString() + ".txt"))) {
			String[] lineParsed = line.split("|", 0);

			String _domain = new String(domain, StandardCharsets.UTF_8);
			String _username = new String(username, StandardCharsets.UTF_8);
			if (lineParsed[0].equals(_domain))
				if (lineParsed[1].equals(_username))
					output = lineParsed[2].getBytes();
		}
		
		return output;
	}
}