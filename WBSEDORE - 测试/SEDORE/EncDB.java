import java.security.NoSuchAlgorithmException;
import it.unisa.dia.gas.jpbc.*;
import java.io.File;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileWriter;

public class EncDB {

    public static void encDataSet(Field<Element> Zr, Element[] sk, Element[][][] ciphertext,  String txt) throws NoSuchAlgorithmException {
        int messageLength = 8; //The maximum bit-length
        BitConverter converter = new BitConverter();

        int[] dataset = new int[8000];
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
        for(int i=0; i<8000; i++) {
            int[] m = converter.intToBinary(dataset[i], messageLength); //Message for DataSet

            //Message hash for encryption
            MessageHash messageHash = new MessageHash();
            Element[][] m_hash = new Element[messageLength][2];
            init.initDimensionTwo_Zr(Zr, m_hash, messageLength, 2);
            messageHash.hash(m_hash, m, messageLength);

            Enc enc = new Enc();
            Element[][] ct = new Element[messageLength][8];
            init.initDimensionTwo_Zr(Zr, ct, messageLength, 8);
            enc.encrypt(Zr, ct, m_hash, messageLength, sk);

            ciphertext[i] = ct;
        }

    }
}
