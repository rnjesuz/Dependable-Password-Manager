import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;

public class PuppetMaster {
	private static int serverAmmount = 4;

	public PuppetMaster() {
	}

	public static void main(String[] args) {
		
		final String dir = System.getProperty("user.dir");
		String[] cmdarray = new String[3];
		cmdarray[0]=dir + "/Server.java";
		try {
			for (int i=0; i<=serverAmmount; i++){
				String port = "808" + Integer.toString(i);
				String[] aux ={"cmd.exe", "/c", "start", "java", "Server", port};
				Process p = Runtime.getRuntime().exec(aux);
			}
		}catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
