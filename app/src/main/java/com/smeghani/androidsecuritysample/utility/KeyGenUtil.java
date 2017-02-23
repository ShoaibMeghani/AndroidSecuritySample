package com.smeghani.androidsecuritysample.utility;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Created by smeghani on 2/23/2017.
 */

public class KeyGenUtil {

    private final String ALIAS = "com.smeghani.androidsecuritysample";
    private final String TRANSFORMATION = "AES/CBC/NoPadding";
    private final String ANDROIDKEYSTORE = "AndroidKeyStore";
    private static byte[] iv;
    private static byte[] encryption;

    public byte[] encryptText(String text) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {

        final KeyGenerator keyGenerator = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROIDKEYSTORE);

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {

            final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build();


            keyGenerator.init(keyGenParameterSpec);
            final SecretKey secretKey = keyGenerator.generateKey();

            final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            iv = cipher.getIV();

            encryption = cipher.doFinal(text.getBytes("UTF-8"));
        }

        return encryption;
    }

    public String decryptText(byte[] encryptionIv, final byte[] encryptedData) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, CertificateException, KeyStoreException, UnrecoverableEntryException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        KeyStore keyStore = KeyStore.getInstance(ANDROIDKEYSTORE);
        keyStore.load(null);
        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec spec = null;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.KITKAT) {
            spec = new GCMParameterSpec(128, encryptionIv);
            cipher.init(Cipher.DECRYPT_MODE, ((KeyStore.SecretKeyEntry) keyStore.getEntry(ALIAS, null)).getSecretKey(), spec);
        }


        return new String(cipher.doFinal(encryptedData), "UTF-8");
    }

    public static byte[] getIv() {
        return iv;
    }

    public static byte[] getEncryption() {
        return encryption;
    }
}
