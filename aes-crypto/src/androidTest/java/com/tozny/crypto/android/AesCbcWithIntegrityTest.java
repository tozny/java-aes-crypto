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
        String plain = AesCbcWithIntegrity.decryptString(AesCbcWithIntegrity.encrypt("some test", keys), keys);
        assertEquals("some test", plain);

    }

}