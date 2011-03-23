package java.util.jar;

import sun.security.util.ManifestEntryVerifier;

import java.contra.ContraUtil;
import java.io.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;


public class JarInputStream extends ZipInputStream {
    private Manifest man;
    private JarEntry first;
    private JarVerifier jv;
    private ManifestEntryVerifier mev;

    private InputStream filter(InputStream in, String des) {

        byte[] file = new byte[0];
        String dir = "./dump/";
        String newname = "NOTSAVED";

        if (!new File(dir).exists()) {
            new File(dir).mkdir();
        }
        try {
            file = getBytes(in);
            if (file.length > 2) {
                newname = dir + man.getMainAttributes().getValue(Attributes.Name.MAIN_CLASS) + System.currentTimeMillis() + ".jar";
                FileOutputStream fos = new FileOutputStream(newname);
                fos.write(file);
                fos.flush();
                fos.close();
            }
        } catch (Exception e) {
            System.out.println("Error dumping via JarInputStream Hook!");
            e.printStackTrace();
        }
        String res = "JarInputStream Hook: Size: " + file.length + " bytes, Location: " + newname + ", Type: " + des;
        ContraUtil.log(res);
        System.out.println(res);
        return in;
    }

    public JarInputStream(InputStream in) throws IOException {
        this(in, true);
    }

    public JarInputStream(InputStream in, boolean verify) throws IOException {
        super(in);
        JarEntry e = (JarEntry) super.getNextEntry();

        if (e != null && e.getName().equalsIgnoreCase("META-INF/"))
            e = (JarEntry) super.getNextEntry();

        if (e != null && JarFile.MANIFEST_NAME.equalsIgnoreCase(e.getName())) {
            man = new Manifest();
            byte bytes[] = getBytes(new BufferedInputStream(this));
            man.read(new ByteArrayInputStream(bytes));
            closeEntry();
            if (verify) {
                jv = new JarVerifier(bytes);
                mev = new ManifestEntryVerifier(man);
            }
            first = getNextJarEntry();
        } else {
            first = e;
        }
        in = filter(in, "New (Verified)");
    }

    private byte[] getBytes(InputStream is)
            throws IOException {
        byte[] buffer = new byte[8192];
        ByteArrayOutputStream baos = new ByteArrayOutputStream(2048);

        int n;

        baos.reset();
        while ((n = is.read(buffer, 0, buffer.length)) != -1) {
            baos.write(buffer, 0, n);
        }
        return baos.toByteArray();
    }

    public Manifest getManifest() {
        return man;
    }

    public ZipEntry getNextEntry() throws IOException {
        JarEntry e;
        if (first == null) {
            e = (JarEntry) super.getNextEntry();
        } else {
            e = first;
            first = null;
        }
        if (jv != null && e != null) {
            if (jv.nothingToVerify() == true) {
                jv = null;
                mev = null;
            } else {
                jv.beginEntry(e, mev);
            }
        }
        return e;
    }

    public JarEntry getNextJarEntry() throws IOException {
        return (JarEntry) getNextEntry();
    }

    public int read(byte[] b, int off, int len) throws IOException {
        int n;
        if (first == null) {
            n = super.read(b, off, len);
        } else {
            n = -1;
        }
        if (jv != null) {
            jv.update(n, b, off, len, mev);
        }
        return n;
    }

    protected ZipEntry createZipEntry(String name) {
        JarEntry e = new JarEntry(name);
        if (man != null) {
            e.attr = man.getAttributes(name);
        }
        return e;
    }
}