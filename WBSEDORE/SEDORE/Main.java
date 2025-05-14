import java.security.NoSuchAlgorithmException;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import sun.awt.windows.WPrinterJob;

public class Main {
	
	@SuppressWarnings("unchecked")
	public static void main(String[] args) throws NoSuchAlgorithmException {
		int messageLength = 8; //The maximum bit-length
		BitConverter converter = new BitConverter();
				
		int[] m1 = converter.intToBinary(124, messageLength); //Message for u
		int[] m2 = converter.intToBinary(124, messageLength); //Message for v
		System.out.print("Binary repr. of m1= ");
		for (int i = 0; i < messageLength; i++)
			System.out.print(m1[i]);
		System.out.println();
		System.out.print("Binary repr. of m2= ");
		for (int i = 0; i < messageLength; i++)
			System.out.print(m2[i]);
		System.out.println();
		System.out.println();
		
		//Setup
		Pairing pairing = PairingFactory.getPairing("d224.properties");
		Field<Element> Zr = pairing.getZr();
		Field<Element> G1 = pairing.getG1();
		Element e2 = G1.newRandomElement();
		//Element initialization
		InitElement init = new InitElement();
		
		
		//Key generation
		KeyGen keygen = new KeyGen();
		Element[] sk_u = new Element[3];
		init.initDimensionOne_Zr(Zr, sk_u, 3);
		Element[] pk_u = new Element[1];
		init.initDimensionOne_G1(G1, pk_u, 1);
		keygen.keygen(Zr, G1, sk_u, pk_u, e2);
		Element[] sk_v = new Element[3];
		init.initDimensionOne_Zr(Zr, sk_v, 3);
		Element[] pk_v = new Element[1];
		init.initDimensionOne_G1(G1, pk_v, 1);
		keygen.keygen(Zr, G1, sk_v, pk_v, e2);
		
		
		//Authorization token generation
		TokGen authorize = new TokGen();
		Element[] tk_v_to_u = new Element[4];
		init.initDimensionOne_G1(G1, tk_v_to_u, 4);
		authorize.authorize(Zr, G1, tk_v_to_u, sk_u, pk_v);
		Element[] tk_u_to_v = new Element[4];
		init.initDimensionOne_G1(G1, tk_u_to_v, 4);
		authorize.authorize(Zr, G1, tk_u_to_v, sk_v, pk_u);
		

		//Message hash for encryption
		MessageHash messageHash = new MessageHash();
		Element[][] m1_hash = new Element[messageLength][2];
		init.initDimensionTwo_Zr(Zr, m1_hash, messageLength, 2);
		messageHash.hash(m1_hash, m1, messageLength);
//		System.out.print("m1_hash= ");
//		for (int i = 0; i < messageLength; i++) {
//			System.out.print("i:");
//			System.out.println(i);
//			System.out.println(m1_hash[i][1]);
//		}
//		System.out.println();
		Element[][] m2_hash = new Element[messageLength][2];
		init.initDimensionTwo_Zr(Zr, m2_hash, messageLength, 2);
		messageHash.hash(m2_hash, m2, messageLength);
//		System.out.print("m2_hash= ");
//		for (int i = 0; i < messageLength; i++) {
//			System.out.print("i:");
//			System.out.println(i);
//			System.out.println(m2_hash[i][0]);
//		}
//		System.out.println();

		//hash encryption
		Enc enc = new Enc();
		Element[][] ct_u = new Element[messageLength][8];
		init.initDimensionTwo_Zr(Zr, ct_u, messageLength, 8);
		enc.encrypt(Zr, ct_u, m1_hash, messageLength, sk_u);
//		System.out.print("ct_u= ");
//		for (int i = 0; i < messageLength; i++) {
//			System.out.print("i:");
//			System.out.println(i);
//			System.out.println(ct_u[i][1]);
//		}
//		System.out.println();
		Element[][] ct_v = new Element[messageLength][8];
		init.initDimensionTwo_Zr(Zr, ct_v, messageLength, 8);
		enc.encrypt(Zr, ct_v, m2_hash, messageLength, sk_v);
//		System.out.print("ct_v= ");
//		for (int i = 0; i < messageLength; i++) {
//			System.out.print("i:");
//			System.out.println(i);
//			System.out.println(ct_v[i][1]);
//		}
//		System.out.println();


		long stime = System.currentTimeMillis();
		//Test to reveal order
		Test test = new Test();		
		int result = test.test(G1, ct_u, ct_v, tk_v_to_u, tk_u_to_v, messageLength);

		long etime = System.currentTimeMillis();
		// 计算执行时间
		System.out.printf("执行时长：%d 毫秒.", (etime - stime));

		if (result == 0)
			System.out.println("Test result: m1 = m2");
		else if (result == 1)
			System.out.println("Test result: m1 > m2");
		else
			System.out.println("Test result: m1 < m2");

	}
}
