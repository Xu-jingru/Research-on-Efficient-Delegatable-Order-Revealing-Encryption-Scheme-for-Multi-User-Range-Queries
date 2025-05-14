import java.security.NoSuchAlgorithmException;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import sun.awt.windows.WPrinterJob;

public class Main {
	
	@SuppressWarnings("unchecked")
	public static void main(String[] args) throws NoSuchAlgorithmException {
		int messageLength = 8; //The maximum bit-length
		BitConverter converter = new BitConverter();

		
		//Setup
		Pairing pairing = PairingFactory.getPairing("d224.properties");
		Field<Element> Zr = pairing.getZr();
		Field<Element> G1 = pairing.getG1();
		Element e = G1.newRandomElement();
		//Element initialization
		InitElement init = new InitElement();
		
		
		//Key generation
		KeyGen keygen = new KeyGen();
		Element[] sk_u = new Element[3];
		init.initDimensionOne_Zr(Zr, sk_u, 3);
		Element[] pk_u = new Element[1];
		init.initDimensionOne_G1(G1, pk_u, 1);
		keygen.keygen(Zr, G1, sk_u, pk_u, e);
		Element[] sk_v = new Element[3];
		init.initDimensionOne_Zr(Zr, sk_v, 3);
		Element[] pk_v = new Element[1];
		init.initDimensionOne_G1(G1, pk_v, 1);
		keygen.keygen(Zr, G1, sk_v, pk_v, e);
		
		
		//Authorization token generation
		TokGen authorize = new TokGen();
		Element[] tk_v_to_u = new Element[4];
		init.initDimensionOne_G1(G1, tk_v_to_u, 4);
		long stime = System.currentTimeMillis();
		authorize.authorize(Zr, G1, tk_v_to_u, sk_u, pk_v);
		long etime = System.currentTimeMillis();
		// 计算执行时间
		System.out.printf("执行时长：%d 毫秒.", (etime - stime));
		System.out.println();
		Element[] tk_u_to_v = new Element[4];
		init.initDimensionOne_G1(G1, tk_u_to_v, 4);
		authorize.authorize(Zr, G1, tk_u_to_v, sk_v, pk_u);


		int[] m_v = converter.intToBinary(54, messageLength); //Message for v
		//Message hash for encryption
		MessageHash messageHash = new MessageHash();
		Element[][] m_v_hash = new Element[messageLength][2];
		init.initDimensionTwo_Zr(Zr, m_v_hash, messageLength, 2);
		messageHash.hash(m_v_hash, m_v, messageLength);
		//hash encryption
		Enc enc = new Enc();
		Element[][] ct_v = new Element[messageLength][8];
		init.initDimensionTwo_Zr(Zr, ct_v, messageLength, 8);
		enc.encrypt(Zr, ct_v, m_v_hash, messageLength, sk_v);

		EncDB encDb = new EncDB();
		Element[][][] ct_u1 = new Element[8000][messageLength][8];
		init.initDimensionThree_Zr(Zr, ct_u1, 8000, messageLength, 8);
		System.out.println("before encDataSet1");
		stime = System.currentTimeMillis();
		encDb.encDataSet(Zr, sk_u, ct_u1, "E:\\Users\\toutou\\Desktop\\WBSEDORE - 测试\\SEDORE\\test1_sorted_8000.txt");
		etime = System.currentTimeMillis();
		System.out.println("after encDataSet1");
		// 计算执行时间
		System.out.printf("执行时长：%d 毫秒.", (etime - stime));
		System.out.println();

		Element[][][] ct_u2 = new Element[8000][messageLength][8];
		init.initDimensionThree_Zr(Zr, ct_u2, 8000, messageLength, 8);
		System.out.println("before encDataSet2");
		stime = System.currentTimeMillis();
		encDb.encDataSet(Zr, sk_u, ct_u2, "E:\\Users\\toutou\\Desktop\\WBSEDORE - 测试\\SEDORE\\test2_sorted_8000.txt");
		etime = System.currentTimeMillis();
		System.out.println("after encDataSet2");
		// 计算执行时间
		System.out.printf("执行时长：%d 毫秒.", (etime - stime));
		System.out.println();

		Element[][][] ct_u3 = new Element[8000][messageLength][8];
		init.initDimensionThree_Zr(Zr, ct_u3, 8000, messageLength, 8);
		System.out.println("before encDataSet3");
		stime = System.currentTimeMillis();
		encDb.encDataSet(Zr, sk_u, ct_u3, "E:\\Users\\toutou\\Desktop\\WBSEDORE - 测试\\SEDORE\\test3_sorted_8000.txt");
		etime = System.currentTimeMillis();
		System.out.println("after encDataSet3");
		// 计算执行时间
		System.out.printf("执行时长：%d 毫秒.", (etime - stime));
		System.out.println();

		Element[][][] ct_u4 = new Element[8000][messageLength][8];
		init.initDimensionThree_Zr(Zr, ct_u4, 8000, messageLength, 8);
		System.out.println("before encDataSet4");
		stime = System.currentTimeMillis();
		encDb.encDataSet(Zr, sk_u, ct_u4, "E:\\Users\\toutou\\Desktop\\WBSEDORE - 测试\\SEDORE\\test4_sorted_8000.txt");
		etime = System.currentTimeMillis();
		System.out.println("after encDataSet4");
		// 计算执行时间
		System.out.printf("执行时长：%d 毫秒.", (etime - stime));
		System.out.println();

		Element[][][] ct_u5 = new Element[8000][messageLength][8];
		init.initDimensionThree_Zr(Zr, ct_u5, 8000, messageLength, 8);
		System.out.println("before encDataSet5");
		stime = System.currentTimeMillis();
		encDb.encDataSet(Zr, sk_u, ct_u5, "E:\\Users\\toutou\\Desktop\\WBSEDORE - 测试\\SEDORE\\test5_sorted_8000.txt");
		etime = System.currentTimeMillis();
		System.out.println("after encDataSet5");
		// 计算执行时间
		System.out.printf("执行时长：%d 毫秒.", (etime - stime));
		System.out.println();


		//Test to reveal order
		Test test = new Test();
		stime = System.currentTimeMillis();
		for(int i=0; i<8000; i++) {
			test.test(G1, ct_u1[i], ct_v, tk_v_to_u, tk_u_to_v, messageLength);
//			if (result == 0)
//				System.out.println(i+":Test result: m1 = m2");
//			else if (result == 1)
//				System.out.println(i+":Test result: m1 > m2");
//			else
//				System.out.println(i+":Test result: m1 < m2");
		}
		etime = System.currentTimeMillis();
		// 计算执行时间
		System.out.printf("dataset1 查询时长：%d 毫秒.", (etime - stime));
		System.out.println();

		stime = System.currentTimeMillis();
		for(int i=0; i<8000; i++) {
			test.test(G1, ct_u2[i], ct_v, tk_v_to_u, tk_u_to_v, messageLength);
		}
		etime = System.currentTimeMillis();
		// 计算执行时间
		System.out.printf("dataset2 查询时长：%d 毫秒.", (etime - stime));
		System.out.println();

		stime = System.currentTimeMillis();
		for(int i=0; i<8000; i++) {
			test.test(G1, ct_u3[i], ct_v, tk_v_to_u, tk_u_to_v, messageLength);
		}
		etime = System.currentTimeMillis();
		// 计算执行时间
		System.out.printf("dataset3 查询时长：%d 毫秒.", (etime - stime));
		System.out.println();

		stime = System.currentTimeMillis();
		for(int i=0; i<8000; i++) {
			test.test(G1, ct_u4[i], ct_v, tk_v_to_u, tk_u_to_v, messageLength);
		}
		etime = System.currentTimeMillis();
		// 计算执行时间
		System.out.printf("dataset4 查询时长：%d 毫秒.", (etime - stime));
		System.out.println();

		stime = System.currentTimeMillis();
		for(int i=0; i<8000; i++) {
			test.test(G1, ct_u5[i], ct_v, tk_v_to_u, tk_u_to_v, messageLength);
		}
		etime = System.currentTimeMillis();
		// 计算执行时间
		System.out.printf("dataset5 查询时长：%d 毫秒.", (etime - stime));
		System.out.println();
	}
}
