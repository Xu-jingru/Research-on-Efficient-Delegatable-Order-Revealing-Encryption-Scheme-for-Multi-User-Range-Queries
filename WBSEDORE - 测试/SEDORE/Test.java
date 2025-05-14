import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class Test {
	Pairing pairing = PairingFactory.getPairing("d224.properties");
	
	public int test(Field<Element> G1, Element[][] ct_u, Element[][] ct_v, Element[] tk_v_to_u, Element[] tk_u_to_v, int messageLength) {
		// Return 0 if m = m', 1 if m < m', 2 if m > m'
		Element T0, T1, T2, T3, T4, T5, T6, T7, d0, d1;
		T0 = G1.newElement();
		T1 = G1.newElement();
		T2 = G1.newElement();
		T3 = G1.newElement();
		T4 = G1.newElement();
		T5 = G1.newElement();
		T6 = G1.newElement();
		T7 = G1.newElement();
		
		for (int i = 0; i < messageLength; i++) {
			//Test-1 (if m_u > m_v)
			Element temp1, temp2, temp3, temp4;

			temp1 = G1.newElement();
			temp1.set(tk_v_to_u[0]);
			temp1.powZn(ct_u[i][0]);

			temp2 = G1.newElement();
			temp2.set(tk_v_to_u[1]);
			temp2.powZn(ct_u[i][1]);

			T0.set(temp1.mul(temp2));

			temp3 = G1.newElement();
			temp3.set(tk_v_to_u[2]);
			temp3.powZn(ct_u[i][2]);

			temp4 = G1.newElement();
			temp4.set(tk_v_to_u[3]);
			temp4.powZn(ct_u[i][3]);

			T1.set(temp3.mul(temp4));

			d0 = G1.newElement();
			d0.set(T0.div(T1));

			temp1.set(tk_u_to_v[0]);
			temp1.powZn(ct_v[i][4]);

			temp2.set(tk_u_to_v[1]);
			temp2.powZn(ct_v[i][5]);

			T2.set(temp1.mul(temp2));

			temp3.set(tk_u_to_v[2]);
			temp3.powZn(ct_v[i][6]);

			temp4.set(tk_u_to_v[3]);
			temp4.powZn(ct_v[i][7]);

			T3.set(temp3.mul(temp4));

			d1 = G1.newElement();
			d1.set(T2.div(T3));

//			System.out.print("i=");
//			System.out.println(i);
//			System.out.println(d0);
//			System.out.println(d1);
		
			if (d0.isEqual(d1))
				return 1;
			
			//Test-2 (if m_u < m_v)
			Element temp5, temp6, temp7, temp8;

			temp5 = G1.newElement();
			temp5.set(tk_v_to_u[0]);
			temp5.powZn(ct_u[i][4]);

			temp6 = G1.newElement();
			temp6.set(tk_v_to_u[1]);
			temp6.powZn(ct_u[i][5]);

			T4.set(temp5.mul(temp6));

			temp7 = G1.newElement();
			temp7.set(tk_v_to_u[2]);
			temp7.powZn(ct_u[i][6]);

			temp8 = G1.newElement();
			temp8.set(tk_v_to_u[3]);
			temp8.powZn(ct_u[i][7]);

			T5.set(temp7.mul(temp8));

			d0 = G1.newElement();
			d0.set(T4.div(T5));

			temp5.set(tk_u_to_v[0]);
			temp5.powZn(ct_v[i][0]);

			temp6.set(tk_u_to_v[1]);
			temp6.powZn(ct_v[i][1]);

			T6.set(temp5.mul(temp6));

			temp7.set(tk_u_to_v[2]);
			temp7.powZn(ct_v[i][2]);

			temp8.set(tk_u_to_v[3]);
			temp8.powZn(ct_v[i][3]);

			T7.set(temp7.mul(temp8));

			d1 = G1.newElement();
			d1.set(T6.div(T7));

//			System.out.print("i=");
//			System.out.println(i);
//			System.out.println(d0);
//			System.out.println(d1);

			if (d0.isEqual(d1))
				return 2;
		}
		
		//Test-3 (if m_u == m_v)
		return 0;
	}
}
