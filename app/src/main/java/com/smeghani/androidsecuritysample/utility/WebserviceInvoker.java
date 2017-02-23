package com.smeghani.androidsecuritysample.utility;

import android.content.Context;
import android.util.Log;

import com.smeghani.androidsecuritysample.R;

import org.json.JSONException;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;

/**
 * Created by smeghani on 2/23/2017.
 */

public class WebserviceInvoker {

    private final int TIMEOUT = 5000;

    //First create the thumbprint using SSLUtil and save it for later comparision
    private final String CERTIFICATE_THUMBPRINT = "";

    private Context context;

    public WebserviceInvoker(Context context) {
        this.context = context;
    }

    private String sendRequestToServer(String URL, String json) throws IOException, JSONException, GeneralSecurityException {
        String response = null;

        java.net.URL url = new URL(URL);

        if (URL.contains("https")) {
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

            ArrayList<Integer> certificateRawFiles = new ArrayList<>();
            certificateRawFiles.add(R.raw.root_certificate);
            certificateRawFiles.add(R.raw.intermediate_certificate);

            conn.setSSLSocketFactory(SSLUtil.getSSLSocketForTLS(context,certificateRawFiles));
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);

            conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setRequestMethod("POST");

            conn.connect();
            Certificate[] certificates = conn.getServerCertificates();

            if (certificates.length > 0){
                Certificate mainCertificate = certificates[0];
                String thumbPrint = SSLUtil.getThumbPrint((X509Certificate) mainCertificate);
                if (!thumbPrint.equals(CERTIFICATE_THUMBPRINT)){
                    throw new SSLHandshakeException("Certificate Pinning failed");
                }
            }

            OutputStream os = conn.getOutputStream();
            os.write(json.getBytes("UTF-8"));
            os.close();

            // read the response
            InputStream in = new BufferedInputStream(conn.getInputStream());
            response = readInputStreamToString(in);

            in.close();
            conn.disconnect();
        }else{
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setRequestMethod("POST");

            OutputStream os = conn.getOutputStream();
            os.write(json.getBytes("UTF-8"));
            os.close();

            // read the response
            InputStream in = new BufferedInputStream(conn.getInputStream());
            response = readInputStreamToString(in);

            in.close();
            conn.disconnect();
        }

        return response;
    }

    private String readInputStreamToString(InputStream is) {
        String result = null;
        StringBuffer sb = new StringBuffer();

        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            String inputLine = "";
            while ((inputLine = br.readLine()) != null) {
                sb.append(inputLine);
            }
            result = sb.toString();
        } catch (Exception e) {
            Log.i("Commonwebservice", "Error reading InputStream");
            result = null;
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                    Log.i("Commonwebservice", "Error closing InputStream");
                }
            }
        }

        return result;
    }


}
