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


    public void testEncryptionDecryptionWithPassword() throws Exception {
        AesCbcWithIntegrity.SecretKeys keys = AesCbcWithIntegrity.generateKeyFromPassword("mypassword", "salty".getBytes());

        //encrypt
        AesCbcWithIntegrity.CipherTextIvMac cipherTextIvMac = AesCbcWithIntegrity.encrypt("some test", keys);
        //store or send to server
        String ciphertextString = cipherTextIvMac.toString();

        //decrypt
        String plainText = AesCbcWithIntegrity.decryptString(cipherTextIvMac, keys);

        assertEquals("some test", plainText);

    }

    public void testEncryptionDecryptionCustomIterationCount() throws Exception {
        AesCbcWithIntegrity.SecretKeys keys = AesCbcWithIntegrity.generateKeyFromPassword("mypassword", "salty".getBytes(), 1000);

        //encrypt
        AesCbcWithIntegrity.CipherTextIvMac cipherTextIvMac = AesCbcWithIntegrity.encrypt("some test", keys);
        //store or send to server
        String ciphertextString = cipherTextIvMac.toString();

        //decrypt
        String plainText = AesCbcWithIntegrity.decryptString(cipherTextIvMac, keys);

        assertEquals("some test", plainText);

    }


    public void testEncryptionDecryptionWithDodgySalt() throws Exception {
        try {
            AesCbcWithIntegrity.SecretKeys keys = AesCbcWithIntegrity.generateKeyFromPassword("mypassword", "ABCD + == + EFG!@$%£|~%  ^%$");
            fail("Salt contains invalid base64 chars, an error should be thrown but wasn't");
        }catch (IllegalArgumentException e){
            //ignore this should happen
        }

    }

}