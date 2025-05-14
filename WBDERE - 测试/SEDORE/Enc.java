import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class Enc {
	
	public void encrypt (Field<Element> Zr, Element[] ct, Element message_hash, Element[] sk) {
		Element T0, T1, T2, T3;

			T0 = Zr.newElement();
			T1 = Zr.newElement();
			T2 = Zr.newElement();
			T3 = Zr.newElement();

			Element temp0, temp1, temp2, temp3;
			temp0 = Zr.newElement();
			temp1 = Zr.newElement();
			temp2 = Zr.newElement();
			temp3 = Zr.newElement();
			Element r0;
			Element n0, n1;
			r0 = Zr.newRandomElement();
			n0 = Zr.newRandomElement();
			n1 = Zr.newRandomElement();
			
			//Compute c_{i}
			temp0.set(r0);
			temp0.mulZn(sk[1]);
			temp0.add(message_hash);
			temp0.mulZn(sk[0]);

			temp1.set(n0);
			T1.set(temp1);

			temp0.sub(temp1.mulZn(sk[2]));
			T0.set(temp0);

			temp2.set(r0);

			temp3.set(n1);
			T3.set(temp3);

			temp2.sub(temp3.mulZn(sk[2]));
			T2.set(temp2);


			//Return c_{i}
			ct[0].set(T0);
			ct[1].set(T1);
			ct[2].set(T2);
			ct[3].set(T3);
		
	}

}
