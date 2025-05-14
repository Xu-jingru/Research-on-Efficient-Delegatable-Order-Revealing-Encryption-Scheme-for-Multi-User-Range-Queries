import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class Main {

	@SuppressWarnings("unchecked")
	public static void main(String[] args) throws NoSuchAlgorithmException {
		//Setup
		Pairing pairing = PairingFactory.getPairing("d224.properties");
		Field<Element> Zr = pairing.getZr();
		Field<Element> G1 = pairing.getG1();
		Field<Element> G2 = pairing.getG2();
		Field<Element> GT = pairing.getGT();
		Element e1 = G1.newRandomElement();
		Element e2 = G2.newRandomElement();
		//Element initialization
		InitElement init = new InitElement();


		//Key generation
		KeyGen keygen = new KeyGen();
		Element[] sk_u = new Element[2];
		init.initDimensionOne_Zr(Zr, sk_u, 2);
		Element[] pk_u = new Element[1];
		init.initDimensionOne_G2(G2, pk_u, 1);
		keygen.keygen(Zr, G2, sk_u, pk_u, e2);
		Element[] sk_v = new Element[2];
		init.initDimensionOne_Zr(Zr, sk_v, 2);
		Element[] pk_v = new Element[1];
		init.initDimensionOne_G2(G2, pk_v, 1);
		keygen.keygen(Zr, G2, sk_v, pk_v, e2);


		//Authorization token generation
		TokGen authorize = new TokGen();
		Element[] tk_v_to_u = new Element[2];
		init.initDimensionOne_G2(G2, tk_v_to_u, 2);
		long stime = System.currentTimeMillis();
		authorize.authorize(Zr, G2, tk_v_to_u, sk_u, pk_v);
		long etime = System.currentTimeMillis();
		System.out.printf("执行时长：%d 毫秒.", (etime - stime));
		System.out.println();
		Element[] tk_u_to_v = new Element[2];
		init.initDimensionOne_G2(G2, tk_u_to_v, 2);
		authorize.authorize(Zr, G2, tk_u_to_v, sk_v, pk_u);


		int m_v = 54; //Message for v
		MessageDigest hasher = MessageDigest.getInstance("SHA-512");
		//Message hash for encryption
		byte[] temp;
		temp = hasher.digest(Integer.toString(m_v).getBytes());
		Element mv_hash = G1.newElement();
		mv_hash = pairing.getG1().newElementFromHash(temp, 0, temp.length);
		//hash encryption
		Enc enc = new Enc();
		Element[] ct_v = new Element[2];
		init.initDimensionOne_G1(G1, ct_v, 2);
		enc.encrypt(Zr, G1, ct_v, mv_hash, sk_v, e1);


		EncDB encDb = new EncDB();
		Element[][] ct_u1 = new Element[8000][2];
		init.initDimensionTwo_G1(G1, ct_u1, 8000, 2);
		System.out.println("before encDataSet1");
		stime = System.currentTimeMillis();
		encDb.encDataSet(Zr, G1, sk_u, ct_u1, "E:\\Users\\toutou\\Desktop\\WBSEDORE - 测试\\SEDORE\\test1_sorted_8000.txt", e1);
		etime = System.currentTimeMillis();
		System.out.println("after encDataSet1");
		System.out.printf("执行时长：%d 毫秒.", (etime - stime));
		System.out.println();

		Element[][] ct_u2 = new Element[8000][2];
		init.initDimensionTwo_G1(G1, ct_u2, 8000, 2);
		System.out.println("before encDataSet2");
		stime = System.currentTimeMillis();
		encDb.encDataSet(Zr, G1, sk_u, ct_u2, "E:\\Users\\toutou\\Desktop\\WBSEDORE - 测试\\SEDORE\\test2_sorted_8000.txt", e1);
		etime = System.currentTimeMillis();
		System.out.println("after encDataSet2");
		System.out.printf("执行时长：%d 毫秒.", (etime - stime));
		System.out.println();

		Element[][] ct_u3 = new Element[8000][2];
		init.initDimensionTwo_G1(G1, ct_u3, 8000, 2);
		System.out.println("before encDataSet3");
		stime = System.currentTimeMillis();
		encDb.encDataSet(Zr, G1, sk_u, ct_u3, "E:\\Users\\toutou\\Desktop\\WBSEDORE - 测试\\SEDORE\\test3_sorted_8000.txt", e1);
		etime = System.currentTimeMillis();
		System.out.println("after encDataSet4");
		System.out.printf("执行时长：%d 毫秒.", (etime - stime));
		System.out.println();

		Element[][] ct_u4 = new Element[8000][2];
		init.initDimensionTwo_G1(G1, ct_u4, 8000, 2);
		System.out.println("before encDataSet4");
		stime = System.currentTimeMillis();
		encDb.encDataSet(Zr, G1, sk_u, ct_u4, "E:\\Users\\toutou\\Desktop\\WBSEDORE - 测试\\SEDORE\\test4_sorted_8000.txt", e1);
		etime = System.currentTimeMillis();
		System.out.println("after encDataSet4");
		System.out.printf("执行时长：%d 毫秒.", (etime - stime));
		System.out.println();

		Element[][] ct_u5 = new Element[8000][2];
		init.initDimensionTwo_G1(G1, ct_u5, 8000, 2);
		System.out.println("before encDataSet5");
		stime = System.currentTimeMillis();
		encDb.encDataSet(Zr, G1, sk_u, ct_u5, "E:\\Users\\toutou\\Desktop\\WBSEDORE - 测试\\SEDORE\\test5_sorted_8000.txt", e1);
		etime = System.currentTimeMillis();
		System.out.println("after encDataSet5");
		System.out.printf("执行时长：%d 毫秒.", (etime - stime));
		System.out.println();


		// Test to reveal order
		Test test = new Test();
		stime = System.currentTimeMillis();
		for(int i=0; i<8000; i++) {
			test.test(GT, ct_u1[i], ct_v, tk_v_to_u, tk_u_to_v);
//			if (result == 1)
//				System.out.println(i+":Test result: m1 = m2");
//			else
//				System.out.println(i+":Test result: m1 != m2");
		}
		etime = System.currentTimeMillis();
		// 计算执行时间
		System.out.printf("dataset1 查询时长：%d 毫秒.", (etime - stime));

		stime = System.currentTimeMillis();
		for(int i=0; i<8000; i++) {
			test.test(GT, ct_u2[i], ct_v, tk_v_to_u, tk_u_to_v);
		}
		etime = System.currentTimeMillis();
		// 计算执行时间
		System.out.printf("dataset2 查询时长：%d 毫秒.", (etime - stime));

		stime = System.currentTimeMillis();
		for(int i=0; i<8000; i++) {
			test.test(GT, ct_u3[i], ct_v, tk_v_to_u, tk_u_to_v);
		}
		etime = System.currentTimeMillis();
		// 计算执行时间
		System.out.printf("dataset3 查询时长：%d 毫秒.", (etime - stime));

		stime = System.currentTimeMillis();
		for(int i=0; i<8000; i++) {
			test.test(GT, ct_u4[i], ct_v, tk_v_to_u, tk_u_to_v);
		}
		etime = System.currentTimeMillis();
		// 计算执行时间
		System.out.printf("dataset4 查询时长：%d 毫秒.", (etime - stime));

		stime = System.currentTimeMillis();
		for(int i=0; i<8000; i++) {
			test.test(GT, ct_u5[i], ct_v, tk_v_to_u, tk_u_to_v);
		}
		etime = System.currentTimeMillis();
		// 计算执行时间
		System.out.printf("dataset5 查询时长：%d 毫秒.", (etime - stime));
	}
}
