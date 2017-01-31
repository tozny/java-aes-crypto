package com.tozny.crypto.android;

import com.tozny.crypto.android.AesCbcWithIntegrity;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 */
public class AesCbcWithIntegrityTest  {

    public AesCbcWithIntegrityTest() {
    }

    @Test
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