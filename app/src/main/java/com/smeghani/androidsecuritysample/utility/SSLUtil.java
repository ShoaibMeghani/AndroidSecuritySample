package com.smeghani.androidsecuritysample.utility;

import android.content.Context;

import com.smeghani.androidsecuritysample.R;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * Created by smeghani on 2/8/2017.
 */

public class SSLUtil {

    /**
     * Creates a unique hex thumbprint for given certificate
     *
     * @param cert Certificate for which hex thumbprint is required (usually fetched from server)
     *
     * */
    public static String getThumbPrint(X509Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] der = cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        return hexify(digest);

    }

    public static String hexify(byte bytes[]) {

        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        StringBuffer buf = new StringBuffer(bytes.length * 2);

        for (int i = 0; i < bytes.length; ++i) {
            buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
            buf.append(hexDigits[bytes[i] & 0x0f]);
        }

        return buf.toString();
    }


    /**
     * Provides custom SSLSocketFactory for which TLS is enabled.
     *
     * @param certList List of certificates to be added in custom trust manager.
     *
     * */
    public static javax.net.ssl.SSLSocketFactory getSSLSocketForTLS(Context context,ArrayList<Integer> certList) throws GeneralSecurityException, IOException {
        ArrayList<Certificate> certificateList = new ArrayList<>();
        KeyStore keyStore = null;

        // Load CAs from an InputStream
        // (could be from a resource or ByteArrayInputStream or ...)
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        for (Integer raw:certList) {
            InputStream caInputStream = context.getResources().openRawResource(raw);
            try {
                certificateList.add(cf.generateCertificate(caInputStream));
            }catch (Exception e){
                System.out.println(e.getMessage());
            }finally {
                caInputStream.close();
            }
        }

        // Create a KeyStore containing our trusted CAs
        String keyStoreType = KeyStore.getDefaultType();
        keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);

        for (int i=0; i < certificateList.size(); i++){
            keyStore.setCertificateEntry("ca"+i,certificateList.get(i));
        }

        // Create a TrustManager that trusts the CAs in our KeyStore
        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);


        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
                .getDefaultAlgorithm());
        kmf.init(keyStore, null);


        /*
         * Creates a socket factory for HttpsURLConnection using JKS
		 * contents
		 */

        final javax.net.ssl.SSLSocketFactory socketFactory
                = new TLSSocketFactory(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return socketFactory;


    }

}
