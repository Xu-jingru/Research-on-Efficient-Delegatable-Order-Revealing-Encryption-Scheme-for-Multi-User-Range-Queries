import java.security.NoSuchAlgorithmException;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class Main {
	
	@SuppressWarnings("unchecked")
	public static void main(String[] args) throws NoSuchAlgorithmException {
		int messageLength = 8; //The maximum bit-length
		BitConverter converter = new BitConverter();

		
		//Setup
		Pairing pairing = PairingFactory.getPairing("d224.properties");
		Field<Element> Zr = pairing.getZr();
		Field<Element> G1 = pairing.getG1();
		Field<Element> G2 = pairing.getG2();
		Field<Element> GT = pairing.getGT();
		Element e1 = G1.newRandomElement();
		Element e2 = G2.newRandomElement();
		
		System.out.printf("G_1.", e1);
		System.out.printf("G_2", e2);
	}
}
