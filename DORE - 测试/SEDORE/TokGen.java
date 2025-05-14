import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class TokGen {
	Pairing pairing = PairingFactory.getPairing("d224.properties");
	
	public void authorize (Field<Element> Zr, Field<Element> G2, Element[] tk_v_to_u, Element[] sk_u, Element[] pk_v) throws NoSuchAlgorithmException {
		MessageDigest hasher = MessageDigest.getInstance("SHA-256");
		Element temp0 = G2.newElement();

		Element temp1 = Zr.newElement();


		temp0.set(pk_v[0]); //g_2^{alpha_v}
		tk_v_to_u[0].set(temp0);

		temp1.set(sk_u[0]);

		long stime = System.currentTimeMillis();

		temp1.mulZn(sk_u[1]); //{alpha_v * alpha_u}
		temp0.powZn(temp1); //g_2^{alpha_v * alpha_u * beta_u}

		long etime = System.currentTimeMillis();
		System.out.printf("令牌生成时长: %d 毫秒.\n", (etime - stime));

		tk_v_to_u[1].set(temp0);
	}
}
