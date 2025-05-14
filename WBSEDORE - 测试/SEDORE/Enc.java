import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class Enc {
	Pairing pairing = PairingFactory.getPairing("d224.properties");
	//Pairing pairing = PairingFactory.getPairing("d159.properties");
	
	public void encrypt (Field<Element> Zr, Element[][] ciphertext, Element[][] message_hash, int messageLength, Element[] sk) {
		Element T0, T1, T2, T3, T4, T5, T6, T7;

		for (int i = 0; i < messageLength; i++) {
			T0 = Zr.newElement();
			T1 = Zr.newElement();
			T2 = Zr.newElement();
			T3 = Zr.newElement();
			T4 = Zr.newElement();
			T5 = Zr.newElement();
			T6 = Zr.newElement();
			T7 = Zr.newElement();

			Element temp0, temp1, temp2, temp3;
			temp0 = Zr.newElement();
			temp1 = Zr.newElement();
			temp2 = Zr.newElement();
			temp3 = Zr.newElement();
			Element r0, r1;
			Element n0, n1, n2, n3;
			r0 = Zr.newRandomElement();
			r1 = Zr.newRandomElement();
			n0 = Zr.newRandomElement();
			n1 = Zr.newRandomElement();
			n2 = Zr.newRandomElement();
			n3 = Zr.newRandomElement();
			
			//Compute c_{i,0}
			temp0.set(r0);
			temp0.mulZn(sk[1]);
			temp0.add(message_hash[i][0]);
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


			//Compute c_{i,1}
			temp0.set(r1);
			temp0.mulZn(sk[1]);
			temp0.add(message_hash[i][1]);
			temp0.mulZn(sk[0]);

			temp1.set(n2);
			T5.set(temp1);

			temp0.sub(temp1.mulZn(sk[2]));
			T4.set(temp0);

			temp2.set(r1);

			temp3.set(n3);
			T7.set(temp3);

			temp2.sub(temp3.mulZn(sk[2]));
			T6.set(temp2);

			//Return c_{i,0} and c_{i,1}
			ciphertext[i][0].set(T0);
			ciphertext[i][1].set(T1);
			ciphertext[i][2].set(T2);
			ciphertext[i][3].set(T3);
			ciphertext[i][4].set(T4);
			ciphertext[i][5].set(T5);
			ciphertext[i][6].set(T6);
			ciphertext[i][7].set(T7);
		}
		
	}

}
