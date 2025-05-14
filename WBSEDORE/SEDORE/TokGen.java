import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class TokGen {
	Pairing pairing = PairingFactory.getPairing("d224.properties");
	
	public void authorize (Field<Element> Zr, Field<Element> G2, Element[] tk_v_to_u, Element[] sk_u, Element[] pk_v) throws NoSuchAlgorithmException {
		MessageDigest hasher = MessageDigest.getInstance("SHA-256");
		Element temp0 = G2.newElement();
		temp0.set(pk_v[0]);
		temp0.powZn(sk_u[0]); //g_2^{alpha_v * alpha_u}
		byte[] G1Bytes = hasher.digest(temp0.toCanonicalRepresentation());

		Element T0, T1, T2, T3;
		T0 = G2.newElement();
		T1 = G2.newElement();
		T2 = G2.newElement();
		T3 = G2.newElement();

		Element temp1, temp2, temp3, temp4;
		temp2 = Zr.newElement();
		temp3 = G2.newElement();
		temp4 = G2.newElement();

		temp1 = pairing.getG1().newElementFromHash(G1Bytes, 0, G1Bytes.length); //F(g_2^{alpha_v * alpha_u})
//		System.out.println(temp1);
		temp2.set(sk_u[0]);	//alpha_u
		temp2.invert();	//alpha_u^-1
//		System.out.println(temp2);
		temp3.set(temp1);
		temp4.set(temp1);
		T0.set(temp3.powZn(temp2)); // F(g_2^{alpha_v * alpha_u})^(alpha_u^-1)
//		System.out.println(T0);
		T2.set(temp4.powZn(sk_u[1])); // F(g_2^{alpha_v * alpha_u})^(beta_u)
		T1.set(temp3.powZn(sk_u[2]));
		T3.set(temp4.powZn(sk_u[2]));
		
		tk_v_to_u[0].set(T0);
		tk_v_to_u[1].set(T1);
		tk_v_to_u[2].set(T2);
		tk_v_to_u[3].set(T3);
	}
}
