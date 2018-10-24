import java.util.Random;

public class GenerateSamples {

	public static void main(String[] args){
		Random rand = new Random();
		rand.setSeed(0x1337);
		for(int i = 0; i < 20; i++){
			System.out.println(rand.nextLong());
		}
	}
}
