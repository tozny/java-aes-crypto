/*
 * Copyright (c) 2014 Tozny LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Created by Isaac Potoczny-Jones on 11/12/14.
 */

package com.tozny.crypto.basicaescbc;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import android.os.Build;
import android.os.Process;
import android.util.Base64;
import android.util.Log;

/**
 * Simple library for the "right" defaults for AES key generation, encryption,
 * and decryption using 256-bit AES, CBC, PKCS7 padding, and a random 16-byte IV
 * with SHA1PRNG.
 */
public class AesCbcPadding {
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS7Padding";
    private static final String CIPHER = "AES";
    private static final String RANDOM_ALGORITHM = "SHA1PRNG";
    private static final int AES_KEY_LENGTH = 256;
    private static final int IV_LENGTH = 16;
    private static final int BASE64_FLAGS = Base64.DEFAULT | Base64.NO_WRAP;
    private static final AtomicBoolean prngFixed = new AtomicBoolean(false);

    /**
     * Converts the given AES key into a base64 encoded string suitable for
     * storage. Sister function of AesKeyFromString.
     *
     * @param aesKey
     * @return a base 64 encoded AES string.
     */
    public static String keyString(SecretKey aesKey) {
        return Base64.encodeToString(aesKey.getEncoded(), BASE64_FLAGS);
    }

    /**
     * An aes key derived from a base64 encoded key. This does not generate the
     * key. It's not random or a PBE key.
     *
     * @param aesKeyStr a base64 encoded AES key.
     * @return an AES key suitable for other functions.
     */
    public static SecretKey key(String aesKeyStr) {
        byte[] aesKeyBytes = Base64.decode(aesKeyStr, BASE64_FLAGS);
        return new SecretKeySpec(aesKeyBytes, 0, aesKeyBytes.length, CIPHER);
    }

    /**
     * A function that generates a random AES key and prints out exceptions but
     * doesn't throw them since none should be encountered. If they are
     * encountered, the return value is null.
     *
     * @return The AES key.
     * @throws GeneralSecurityException if AES is not implemented on this system,
     *                                  or a suitable RNG is not available
     */
    public static SecretKey generateKey() throws GeneralSecurityException {
        fixPrng();
        KeyGenerator keyGen = KeyGenerator.getInstance(CIPHER);
        // No need to provide a SecureRandom or set a seed since that will
        // happen automatically.
        keyGen.init(AES_KEY_LENGTH);
        return keyGen.generateKey();
    }

    /**
     * Creates a random Initialization Vector (IV) of IV_LENGTH.
     *
     * @return The byte array of this IV
     * @throws GeneralSecurityException if a suitable RNG is not available
     */
    public static byte[] generateIv() throws GeneralSecurityException {
        fixPrng();
        SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        return iv;
    }

    /*
     * -----------------------------------------------------------------
     * Encryption
     * -----------------------------------------------------------------
     */

    /**
     * Generates a random IV and encrypts this plain text with the given key.
     *
     * @param plaintext The text that will be encrypted, which
     *                  will be serialized with UTF-8
     * @param secretKey The AES key with which to encrypt
     * @return a tuple of the IV and the ciphertext
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if UTF-8 is not supported in this system
     */
    public static CipherTextAndIv encrypt(String plaintext, SecretKey secretKey)
            throws UnsupportedEncodingException, GeneralSecurityException {
        return encrypt(plaintext, secretKey, "UTF-8");
    }

    /**
     * Generates a random IV and encrypts this plain text with the given key.
     *
     * @param plaintext The bytes that will be encrypted
     * @param secretKey The AES key with which to encrypt
     * @return a tuple of the IV and the ciphertext
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if the specified encoding is invalid
     */
    public static CipherTextAndIv encrypt(String plaintext, SecretKey secretKey, String encoding)
            throws UnsupportedEncodingException, GeneralSecurityException {
        return encrypt(plaintext.getBytes(encoding), secretKey);
    }

    /**
     * Generates a random IV and encrypts this plain text with the given key.
     *
     * @param plaintext The text that will be encrypted
     * @param secretKey The AES key with which to encrypt
     * @return a tuple of the IV and the ciphertext
     * @throws GeneralSecurityException if AES is not implemented on this system
     */
    public static CipherTextAndIv encrypt(byte[] plaintext, SecretKey secretKey)
            throws GeneralSecurityException {
        byte[] iv = generateIv();
        Cipher aesCipherForEncryption = Cipher.getInstance(CIPHER_TRANSFORMATION);
        aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

        /*
         * Now we get back the IV that will actually be used. Some Android
         * versions do funny stuff w/ the IV, so this is to work around bugs:
         */
        iv = aesCipherForEncryption.getIV();
        byte[] byteCipherText = aesCipherForEncryption.doFinal(plaintext);
        return new CipherTextAndIv(byteCipherText, iv);
    }

    /**
     * Ensures that the PRNG is fixed. Should be used before generating any keys.
     * Will only run once, and every subsequent call should return immediately.
     */
    private static void fixPrng() {
        if (!prngFixed.get()) {
            synchronized (PrngFixes.class) {
                if (!prngFixed.get()) {
                    PrngFixes.apply();
                    prngFixed.set(true);
                }
            }
        }
    }

    /*
     * -----------------------------------------------------------------
     * Decryption
     * -----------------------------------------------------------------
     */

    /**
     * AES CBC decrypt.
     *
     * @param civ The cipher text and IV
     * @param secretKey The AES key
     * @param The string encoding to use to decode the bytes after decryption
     * @return A string derived from the decrypted bytes (not base64 encoded)
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if the encoding is unsupported
     */
    public static String decryptString(CipherTextAndIv civ, SecretKey secretKey, String encoding)
            throws UnsupportedEncodingException, GeneralSecurityException {
        return new String(decrypt(civ, secretKey), encoding);
    }

    /**
     * AES CBC decrypt.
     *
     * @param civ The cipher text and IV
     * @param secretKey The AES key
     * @return A string derived from the decrypted bytes, which are interpreted
     *         as a UTF-8 String
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if UTF-8 is not supported
     */
    public static String decryptString(CipherTextAndIv civ, SecretKey secretKey)
            throws UnsupportedEncodingException, GeneralSecurityException {
        return decryptString(civ, secretKey, "UTF-8");
    }

    /**
     * AES CBC decrypt.
     *
     * @param civ the cipher text and iv
     * @param secretKey the AES key
     * @return The raw decrypted bytes
     * @throws GeneralSecurityException if AES is not implemented on this system
     */
    public static byte[] decrypt(CipherTextAndIv civ, SecretKey secretKey)
            throws GeneralSecurityException {
        Cipher aesCipherForDecryption = Cipher.getInstance(CIPHER_TRANSFORMATION);
        aesCipherForDecryption.init(Cipher.DECRYPT_MODE, secretKey,
                new IvParameterSpec(civ.getIv()));
        return aesCipherForDecryption.doFinal(civ.getCipherText());
    }

    /*
     * ----------------------------------------------------------------- Helper
     * Code -----------------------------------------------------------------
     */

    /**
     * Holder class that allows us to bundle ciphertext and IV together.
     */
    public static class CipherTextAndIv {
        private final byte[] cipherText;
        private final byte[] iv;

        public byte[] getCipherText() {
            return cipherText;
        }

        public byte[] getIv() {
            return iv;
        }

        /**
         * Construct a new bundle of ciphertext and IV.
         *
         * @param c The ciphertext
         * @param i The IV
         */
        public CipherTextAndIv(byte[] c, byte[] i) {
            cipherText = Arrays.copyOf(c, c.length);
            iv = Arrays.copyOf(i, i.length);
        }

        /**
         * Constructs a new bundle of ciphertext and IV from a string of the
         * format <code>base64(iv):base64(ciphertext)</code>.
         *
         * @param base64IvAndCiphertext A string of the format
         *            <code>iv:ciphertext</code> The IV and ciphertext must each
         *            be base64-encoded.
         */
        public CipherTextAndIv(String base64IvAndCiphertext) {
            String[] civArray = base64IvAndCiphertext.split(":");
            if (civArray.length != 2) {
                throw new IllegalArgumentException();
            } else {
                iv = Base64.decode(civArray[0], BASE64_FLAGS);
                cipherText = Base64.decode(civArray[1], BASE64_FLAGS);
            }
        }

        /**
         * Encodes this ciphertext and IV pair as a string.
         *
         * @return base64(iv) : base64(ciphertext). The iv goes first because
         *         it's a fixed length.
         */
        @Override
        public String toString() {
            String ivString = Base64.encodeToString(iv, BASE64_FLAGS);
            String cipherTextString = Base64.encodeToString(cipherText, BASE64_FLAGS);
            return String.format(ivString + ":" + cipherTextString);
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + Arrays.hashCode(cipherText);
            result = prime * result + Arrays.hashCode(iv);
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            CipherTextAndIv other = (CipherTextAndIv) obj;
            if (!Arrays.equals(cipherText, other.cipherText))
                return false;
            if (!Arrays.equals(iv, other.iv))
                return false;
            return true;
        }
    }

    /**
     * Fixes for the RNG as per
     * http://android-developers.blogspot.com/2013/08/some-securerandom-thoughts.html
     *
     * This software is provided 'as-is', without any express or implied
     * warranty. In no event will Google be held liable for any damages arising
     * from the use of this software.
     *
     * Permission is granted to anyone to use this software for any purpose,
     * including commercial applications, and to alter it and redistribute it
     * freely, as long as the origin is not misrepresented.
     *
     * Fixes for the output of the default PRNG having low entropy.
     *
     * The fixes need to be applied via {@link #apply()} before any use of Java
     * Cryptography Architecture primitives. A good place to invoke them is in
     * the application's {@code onCreate}.
     */
    public static final class PrngFixes {

        private static final int VERSION_CODE_JELLY_BEAN = 16;
        private static final int VERSION_CODE_JELLY_BEAN_MR2 = 18;
        private static final byte[] BUILD_FINGERPRINT_AND_DEVICE_SERIAL = getBuildFingerprintAndDeviceSerial();

        /** Hidden constructor to prevent instantiation. */
        private PrngFixes() {
        }

        /**
         * Applies all fixes.
         *
         * @throws SecurityException if a fix is needed but could not be
         *             applied.
         */
        public static void apply() {
            applyOpenSSLFix();
            installLinuxPRNGSecureRandom();
        }

        /**
         * Applies the fix for OpenSSL PRNG having low entropy. Does nothing if
         * the fix is not needed.
         *
         * @throws SecurityException if the fix is needed but could not be
         *             applied.
         */
        private static void applyOpenSSLFix() throws SecurityException {
            if ((Build.VERSION.SDK_INT < VERSION_CODE_JELLY_BEAN)
                    || (Build.VERSION.SDK_INT > VERSION_CODE_JELLY_BEAN_MR2)) {
                // No need to apply the fix
                return;
            }

            try {
                // Mix in the device- and invocation-specific seed.
                Class.forName("org.apache.harmony.xnet.provider.jsse.NativeCrypto")
                        .getMethod("RAND_seed", byte[].class).invoke(null, generateSeed());

                // Mix output of Linux PRNG into OpenSSL's PRNG
                int bytesRead = (Integer) Class
                        .forName("org.apache.harmony.xnet.provider.jsse.NativeCrypto")
                        .getMethod("RAND_load_file", String.class, long.class)
                        .invoke(null, "/dev/urandom", 1024);
                if (bytesRead != 1024) {
                    throw new IOException("Unexpected number of bytes read from Linux PRNG: "
                            + bytesRead);
                }
            } catch (Exception e) {
                throw new SecurityException("Failed to seed OpenSSL PRNG", e);
            }
        }

        /**
         * Installs a Linux PRNG-backed {@code SecureRandom} implementation as
         * the default. Does nothing if the implementation is already the
         * default or if there is not need to install the implementation.
         *
         * @throws SecurityException if the fix is needed but could not be
         *             applied.
         */
        private static void installLinuxPRNGSecureRandom() throws SecurityException {
            if (Build.VERSION.SDK_INT > VERSION_CODE_JELLY_BEAN_MR2) {
                // No need to apply the fix
                return;
            }

            // Install a Linux PRNG-based SecureRandom implementation as the
            // default, if not yet installed.
            Provider[] secureRandomProviders = Security.getProviders("SecureRandom.SHA1PRNG");
            if ((secureRandomProviders == null)
                    || (secureRandomProviders.length < 1)
                    || (!LinuxPRNGSecureRandomProvider.class.equals(secureRandomProviders[0]
                            .getClass()))) {
                Security.insertProviderAt(new LinuxPRNGSecureRandomProvider(), 1);
            }

            // Assert that new SecureRandom() and
            // SecureRandom.getInstance("SHA1PRNG") return a SecureRandom backed
            // by the Linux PRNG-based SecureRandom implementation.
            SecureRandom rng1 = new SecureRandom();
            if (!LinuxPRNGSecureRandomProvider.class.equals(rng1.getProvider().getClass())) {
                throw new SecurityException("new SecureRandom() backed by wrong Provider: "
                        + rng1.getProvider().getClass());
            }

            SecureRandom rng2;
            try {
                rng2 = SecureRandom.getInstance("SHA1PRNG");
            } catch (NoSuchAlgorithmException e) {
                throw new SecurityException("SHA1PRNG not available", e);
            }
            if (!LinuxPRNGSecureRandomProvider.class.equals(rng2.getProvider().getClass())) {
                throw new SecurityException(
                        "SecureRandom.getInstance(\"SHA1PRNG\") backed by wrong" + " Provider: "
                                + rng2.getProvider().getClass());
            }
        }

        /**
         * {@code Provider} of {@code SecureRandom} engines which pass through
         * all requests to the Linux PRNG.
         */
        private static class LinuxPRNGSecureRandomProvider extends Provider {

            public LinuxPRNGSecureRandomProvider() {
                super("LinuxPRNG", 1.0, "A Linux-specific random number provider that uses"
                        + " /dev/urandom");
                // Although /dev/urandom is not a SHA-1 PRNG, some apps
                // explicitly request a SHA1PRNG SecureRandom and we thus need
                // to prevent them from getting the default implementation whose
                // output may have low entropy.
                put("SecureRandom.SHA1PRNG", LinuxPRNGSecureRandom.class.getName());
                put("SecureRandom.SHA1PRNG ImplementedIn", "Software");
            }
        }

        /**
         * {@link SecureRandomSpi} which passes all requests to the Linux PRNG (
         * {@code /dev/urandom}).
         */
        public static class LinuxPRNGSecureRandom extends SecureRandomSpi {

            /*
             * IMPLEMENTATION NOTE: Requests to generate bytes and to mix in a
             * seed are passed through to the Linux PRNG (/dev/urandom).
             * Instances of this class seed themselves by mixing in the current
             * time, PID, UID, build fingerprint, and hardware serial number
             * (where available) into Linux PRNG.
             *
             * Concurrency: Read requests to the underlying Linux PRNG are
             * serialized (on sLock) to ensure that multiple threads do not get
             * duplicated PRNG output.
             */

            private static final File URANDOM_FILE = new File("/dev/urandom");

            private static final Object sLock = new Object();

            /**
             * Input stream for reading from Linux PRNG or {@code null} if not
             * yet opened.
             *
             * @GuardedBy("sLock")
             */
            private static DataInputStream sUrandomIn;

            /**
             * Output stream for writing to Linux PRNG or {@code null} if not
             * yet opened.
             *
             * @GuardedBy("sLock")
             */
            private static OutputStream sUrandomOut;

            /**
             * Whether this engine instance has been seeded. This is needed
             * because each instance needs to seed itself if the client does not
             * explicitly seed it.
             */
            private boolean mSeeded;

            @Override
            protected void engineSetSeed(byte[] bytes) {
                try {
                    OutputStream out;
                    synchronized (sLock) {
                        out = getUrandomOutputStream();
                    }
                    out.write(bytes);
                    out.flush();
                } catch (IOException e) {
                    // On a small fraction of devices /dev/urandom is not
                    // writable Log and ignore.
                    Log.w(PrngFixes.class.getSimpleName(), "Failed to mix seed into "
                            + URANDOM_FILE);
                } finally {
                    mSeeded = true;
                }
            }

            @Override
            protected void engineNextBytes(byte[] bytes) {
                if (!mSeeded) {
                    // Mix in the device- and invocation-specific seed.
                    engineSetSeed(generateSeed());
                }

                try {
                    DataInputStream in;
                    synchronized (sLock) {
                        in = getUrandomInputStream();
                    }
                    synchronized (in) {
                        in.readFully(bytes);
                    }
                } catch (IOException e) {
                    throw new SecurityException("Failed to read from " + URANDOM_FILE, e);
                }
            }

            @Override
            protected byte[] engineGenerateSeed(int size) {
                byte[] seed = new byte[size];
                engineNextBytes(seed);
                return seed;
            }

            private DataInputStream getUrandomInputStream() {
                synchronized (sLock) {
                    if (sUrandomIn == null) {
                        // NOTE: Consider inserting a BufferedInputStream
                        // between DataInputStream and FileInputStream if you need
                        // higher PRNG output performance and can live with future PRNG
                        // output being pulled into this process prematurely.
                        try {
                            sUrandomIn = new DataInputStream(new FileInputStream(URANDOM_FILE));
                        } catch (IOException e) {
                            throw new SecurityException("Failed to open " + URANDOM_FILE
                                    + " for reading", e);
                        }
                    }
                    return sUrandomIn;
                }
            }

            private OutputStream getUrandomOutputStream() throws IOException {
                synchronized (sLock) {
                    if (sUrandomOut == null) {
                        sUrandomOut = new FileOutputStream(URANDOM_FILE);
                    }
                    return sUrandomOut;
                }
            }
        }

        /**
         * Generates a device- and invocation-specific seed to be mixed into the
         * Linux PRNG.
         */
        private static byte[] generateSeed() {
            try {
                ByteArrayOutputStream seedBuffer = new ByteArrayOutputStream();
                DataOutputStream seedBufferOut = new DataOutputStream(seedBuffer);
                seedBufferOut.writeLong(System.currentTimeMillis());
                seedBufferOut.writeLong(System.nanoTime());
                seedBufferOut.writeInt(Process.myPid());
                seedBufferOut.writeInt(Process.myUid());
                seedBufferOut.write(BUILD_FINGERPRINT_AND_DEVICE_SERIAL);
                seedBufferOut.close();
                return seedBuffer.toByteArray();
            } catch (IOException e) {
                throw new SecurityException("Failed to generate seed", e);
            }
        }

        /**
         * Gets the hardware serial number of this device.
         *
         * @return serial number or {@code null} if not available.
         */
        private static String getDeviceSerialNumber() {
            // We're using the Reflection API because Build.SERIAL is only
            // available since API Level 9 (Gingerbread, Android 2.3).
            try {
                return (String) Build.class.getField("SERIAL").get(null);
            } catch (Exception ignored) {
                return null;
            }
        }

        private static byte[] getBuildFingerprintAndDeviceSerial() {
            StringBuilder result = new StringBuilder();
            String fingerprint = Build.FINGERPRINT;
            if (fingerprint != null) {
                result.append(fingerprint);
            }
            String serial = getDeviceSerialNumber();
            if (serial != null) {
                result.append(serial);
            }
            try {
                return result.toString().getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException("UTF-8 encoding not supported");
            }
        }
    }
}