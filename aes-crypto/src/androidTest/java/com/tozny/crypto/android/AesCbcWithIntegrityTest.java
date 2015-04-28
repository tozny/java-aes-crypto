package com.tozny.crypto.android;

import android.test.AndroidTestCase;

/**
 * <a href="http://d.android.com/tools/testing/testing_android.html">Testing Fundamentals</a>
 */
public class AesCbcWithIntegrityTest extends AndroidTestCase {

    public AesCbcWithIntegrityTest() {
    }

    public void testEncryptionDecryptionWorks() throws Exception {
        AesCbcWithIntegrity.SecretKeys keys = AesCbcWithIntegrity.generateKey();

        //encrypt
        AesCbcWithIntegrity.CipherTextIvMac cipherTextIvMac = AesCbcWithIntegrity.encrypt("some test", keys);
        //store or send to server
        String ciphertextString = cipherTextIvMac.toString();

        //decrypt
        String plainText = AesCbcWithIntegrity.decryptString(cipherTextIvMac, keys);

        assertEquals("some test", plainText);



    }

}