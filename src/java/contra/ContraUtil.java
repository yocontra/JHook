package java.contra;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

public class ContraUtil {
    public static boolean log(String str) {
        try {
            File f = new File("./dump/");
            if (!f.exists()) {
                f.mkdir();
            }
            FileWriter fstream = new FileWriter("./dump/log.txt", true);
            BufferedWriter out = new BufferedWriter(fstream);
            out.write("[" + System.currentTimeMillis() + "] " + str + "\r\n");
            out.close();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
