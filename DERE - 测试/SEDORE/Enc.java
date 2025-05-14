import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class Enc {
	Pairing pairing = PairingFactory.getPairing("d224.properties");
	//Pairing pairing = PairingFactory.getPairing("d159.properties");
	
	public void encrypt (Field<Element> Zr, Field<Element> G1, Element[] ciphertext, Element message_hash, Element[] sk, Element e1) {

			Element temp0, temp1;
			temp0 = G1.newElement();
			temp1 = G1.newElement();
			Element r;
			r = Zr.newRandomElement();
			
			//Compute c_{i,0}
			temp0.set(e1);
			temp0.powZn(Zr.newOneElement().mulZn(r).mulZn(sk[1]));
			temp0.mul(message_hash);
			temp0.powZn(sk[0]);

			//Compute c_{i,1}
			temp1.set(e1);
			temp1.powZn(r);
			
			//Return c_{i,0} and c_{i,1}
			ciphertext[0].set(temp0);
			ciphertext[1].set(temp1);
		
	}

}
