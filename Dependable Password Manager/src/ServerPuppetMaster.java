import java.io.IOException;
import java.lang.Runtime;

public class ServerPuppetMaster {

	private static int serverAmmount = 2;

	public ServerPuppetMaster() {
		// TODO Auto-generated constructor stub
	}

	public static void main(String[] args) {
		
		final String dir = System.getProperty("user.dir");
		String[] cmdarray = new String[3];
		cmdarray[0]=dir + "/Server.java";
		
		try {
			for(int i=0; i < serverAmmount; i++){
				if(i==0){
					System.out.println("batata");
					//ip = 8080 for master server
					cmdarray[1]="8080";
					//id = i = 0
					cmdarray[2]= Integer.toString(i);
					
					Runtime.getRuntime().exec("java Server.java");
				}
				else {
					System.out.println("pudim");
					//ip = 0 = randomly selected to fit available port
					cmdarray[1]="0";
					//id = i
					cmdarray[2]= Integer.toString(i);
					
					Runtime.getRuntime().exec("java Server.java");
					}
				}
			}catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					}
		
	}
}
