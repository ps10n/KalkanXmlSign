package KalkanXmlSign;

import com.google.common.io.Files;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

class FileSystemFunctions {

    static X509Certificate loadCertFromFile(String fileName, String fileType, String pass) {
        X509Certificate cert = null;
        KeyStore store;
        byte[] buf;
        try {
            File initialFile = new File(fileName);
            InputStream f = Files.asByteSource(initialFile).openStream();
            //InputStream f = FileSystemFunctions.class.getClassLoader().getResourceAsStream(fileName);
            buf = new byte[f.available()];
            f.read(buf, 0, f.available());
            f.close();
            store = KeyStore.getInstance(fileType, KalkanProvider.PROVIDER_NAME);
            store.load(new ByteArrayInputStream(buf), pass.toCharArray());
            Enumeration en = store.aliases();
            String alias = null;
            while (en.hasMoreElements()) alias = en.nextElement().toString();
            cert = (X509Certificate) store.getCertificateChain(alias)[0];
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return cert;
    }

    static PrivateKey loadKeyFromFile(String fileName, String fileType, String pass) {
        PrivateKey privKey = null;
        KeyStore store;
        byte[] buf;
        try {
            File initialFile = new File(fileName);
            InputStream f = Files.asByteSource(initialFile).openStream();
            //InputStream f = FileSystemFunctions.class.getClassLoader().getResourceAsStream(fileName);
            buf = new byte[f.available()];
            f.read(buf, 0, f.available());
            f.close();
            store = KeyStore.getInstance(fileType, KalkanProvider.PROVIDER_NAME);
            store.load(new ByteArrayInputStream(buf), pass.toCharArray());
            Enumeration en = store.aliases();
            String alias = null;
            while (en.hasMoreElements()) alias = en.nextElement().toString();
            privKey = (PrivateKey) store.getKey(alias, pass.toCharArray());
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return privKey;
    }

    static String validCertFromFile(String fileName, String fileType, String pass) {
        X509Certificate cert = null;
        KeyStore store;
        byte[] buf;
        String msg = "";
        try {
            File initialFile = new File(fileName);
            InputStream f = Files.asByteSource(initialFile).openStream();
            //InputStream f = FileSystemFunctions.class.getClassLoader().getResourceAsStream(fileName);
            buf = new byte[f.available()];
            f.read(buf, 0, f.available());
            f.close();
            store = KeyStore.getInstance(fileType, KalkanProvider.PROVIDER_NAME);
            store.load(new ByteArrayInputStream(buf), pass.toCharArray());
            Enumeration en = store.aliases();
            String alias = null;
            while (en.hasMoreElements()) alias = en.nextElement().toString();
            final X509Certificate cert_v = (X509Certificate) store.getCertificate(alias);
            Date dt_aftr = cert_v.getNotAfter();
            Date dt_now = new Date();
            String sign_alg = cert_v.getSigAlgName();
            if (!sign_alg.contains("ECGOST34310")) {
                msg = "Gateway : Sign Algorithm is not corrected. Please change Cert to GOST_*.";
                throw new Exception(msg);
            }
            if (dt_now.after(dt_aftr)) {
                msg = "Gateway : Date of Certificate is expired.";
                throw new Exception(msg);
            }
            msg = "Ok";
        } catch (Exception ex) {
            msg = ex.getMessage();
            ex.printStackTrace();
        }
        return msg;
    }

    private byte[] readData(final String fileName) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(fileName);
            int size = fis.available();
            byte[] result = new byte[size];
            fis.read(result, 0, size);
            return result;
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
