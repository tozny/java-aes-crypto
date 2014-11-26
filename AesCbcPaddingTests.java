/*
mkdir out
javac -d out -cp bcprov-jdk16-140.jar:hamcrest-core-1.3.jar:junit-4.11.jar:android.jar AesCbcPadding.java AesCbcPaddingTests.java
java -cp jdk16-140.jar:hamcrest-core-1.3.jar:junit-4.11.jar:android.jar:out org.junit.runner.JUnitCore com.tozny.crypto.basicaescbc.AesCbcPaddingTests
exit

You can run this like ./AesCbcPaddingTests.java, assuming you have the above jars in this same
directory.
*/

package com.tozny.crypto.basicaescbc;

import org.junit.Test;
import static org.junit.Assert.*;

public class AesCbcPaddingTests {
    @Test
    public void testEncryptionDecryptionWorks() throws Exception {
        AesCbcPadding.prngFixed.set(true);
        AesCbcPadding.SecretKeys keys = AesCbcPadding.generateKey();
        String plain = AesCbcPadding.decryptString(AesCbcPadding.encrypt("some test", keys), keys);
        assertEquals("some test", plain);
    }
}