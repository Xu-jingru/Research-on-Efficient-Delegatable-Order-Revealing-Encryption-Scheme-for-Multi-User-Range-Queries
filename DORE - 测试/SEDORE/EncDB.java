import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;

public class EncDB {

    public static void encDataSet(Field<Element> Zr, Field<Element> G1, Element[] sk, Element[][][] ciphertext, String txt, Element e1) throws NoSuchAlgorithmException {
        int messageLength = 8; //The maximum bit-length
        BitConverter converter = new BitConverter();

        int[] dataset = new int[2000];
        // read dataset txt
        try { // 防止文件建立或读取失败，用catch捕捉错误并打印，也可以throw
            /* 读入TXT文件 */
            String pathname = txt;
            File filename = new File(pathname);
            InputStreamReader reader = new InputStreamReader(
                    new FileInputStream(filename)); // 建立一个输入流对象reader
            BufferedReader br = new BufferedReader(reader); // 建立一个对象，它把文件内容转成计算机能读懂的语言
            String line = null;
            int linecount = 0;
            while ((line = br.readLine()) != null) {
                dataset[linecount++] = Integer.parseInt(line);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }


        //Element initialization
        InitElement init = new InitElement();
        for(int i=0; i<2000; i++) {
            int[] m = converter.intToBinary(dataset[i], messageLength); //Message for DataSet

            //Message hash for encryption
            MessageHash messageHash = new MessageHash();
            Element[][] m_hash = new Element[messageLength][2];
            init.initDimensionTwo_G1(G1, m_hash, messageLength, 2);
            messageHash.hash(m_hash, m, messageLength);

            Enc enc = new Enc();
            Element[][] ct = new Element[messageLength][8];
            init.initDimensionTwo_G1(G1, ct, messageLength, 8);
            enc.encrypt(Zr, G1, ct, m_hash, messageLength, sk, e1);

            ciphertext[i] = ct;
        }

    }
}
