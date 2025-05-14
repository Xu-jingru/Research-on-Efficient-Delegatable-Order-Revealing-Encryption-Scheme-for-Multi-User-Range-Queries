import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class Test {
	Pairing pairing = PairingFactory.getPairing("d224.properties");
	
	public int test(Field<Element> G1, Element[] ct_u, Element[] ct_v, Element[] tk_v_to_u, Element[] tk_u_to_v, int messageLength) {
		// Return 0 if m = m', 1 if m < m', 2 if m > m'
		Element T0, T1, T2, T3, d0, d1;
		T0 = G1.newElement();
		T1 = G1.newElement();
		T2 = G1.newElement();
		T3 = G1.newElement();

			//Test-1 (if m_u > m_v)
			Element temp1, temp2, temp3, temp4;

			temp1 = G1.newElement();
			temp1.set(tk_v_to_u[0]);
			temp1.powZn(ct_u[0]);

			temp2 = G1.newElement();
			temp2.set(tk_v_to_u[1]);
			temp2.powZn(ct_u[1]);

			T0.set(temp1.mul(temp2));

			temp3 = G1.newElement();
			temp3.set(tk_v_to_u[2]);
			temp3.powZn(ct_u[2]);

			temp4 = G1.newElement();
			temp4.set(tk_v_to_u[3]);
			temp4.powZn(ct_u[3]);

			T1.set(temp3.mul(temp4));

			d0 = G1.newElement();
			d0.set(T0.div(T1));

			temp1.set(tk_u_to_v[0]);
			temp1.powZn(ct_v[0]);

			temp2.set(tk_u_to_v[1]);
			temp2.powZn(ct_v[1]);

			T2.set(temp1.mul(temp2));

			temp3.set(tk_u_to_v[2]);
			temp3.powZn(ct_v[2]);

			temp4.set(tk_u_to_v[3]);
			temp4.powZn(ct_v[3]);

			T3.set(temp3.mul(temp4));

			d1 = G1.newElement();
			d1.set(T2.div(T3));

//			System.out.print("i=");
//			System.out.println(i);
//			System.out.println(d0);
//			System.out.println(d1);
		
			if (d0.isEqual(d1))
				return 1;
			else return 0;
	}
}
