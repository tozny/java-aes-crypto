package crypto.tozny.com.basicaescbclibrary;

import android.util.Base64;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by Isaac Potoczny-Jones on 11/12/14.
 * Copyright (C) 2014 Tozny LLC
 * Simple library for the "right" defaults for AES key generation,
 * encryption, and decryption.
 * AES 256 bit
 * CBC
 * PKCS7 Padding
 * Random 16 byte IV with SHA1PRNG
 */
public class AesCbcPadding {
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS7Padding";
    private static final String CIPHER           = "AES";
    private static final String RANDOM_ALGORITHM = "SHA1PRNG";
    private static final int    AES_KEY_LENGTH   = 256;
    private static final int    IV_LENGTH        = 16;
    private static final int    BASE64_FLAGS     = Base64.DEFAULT | Base64.NO_WRAP;

    /* -----------------------------------------------------------------
    Helper Code
    ----------------------------------------------------------------- */

    /**
     * This little internal class encapsulates the fact that the cryptotext and the
     * iv should typically travel together. use toString and the String constructor
     * to
     */
    public static class CipherTextAndIV {
        byte[] cipherText;
        byte[] iv;

        /**
         *
         * @param c The ciphertext
         * @param i The iv
         */
        public CipherTextAndIV(byte[] c, byte[] i) {
            cipherText = c;
            iv = i;
        }

        /**
         *
         * @param base64IvAndCiphertext A string of the format iv:ciphertext. The iv
         *                              and ciphertext must each base base64 encoded.
         *                              Sister function of toString.
         */
        public CipherTextAndIV (String base64IvAndCiphertext) {
            String[] civArray = base64IvAndCiphertext.split(":");
            if (civArray.length != 2) {
                throw new IllegalArgumentException();
            } else {
                iv         = Base64.decode(civArray[0], BASE64_FLAGS);
                cipherText = Base64.decode(civArray[1], BASE64_FLAGS);
            }
        }

        /**
         *
         * @return base64(iv) : base64(ciphertext). The iv goes first because it's
         * a fixed length.
         */
        @Override
        public String toString() {
            String ivString         = Base64.encodeToString(iv,         BASE64_FLAGS);
            String cipherTextString = Base64.encodeToString(cipherText, BASE64_FLAGS);
            return String.format( ivString + ":" + cipherTextString);
        }
    }

    /**
     * Converts the given AES key into a base64 encoded string suitable for storage.
     * Sister function of AesKeyFromString.
     * @param aesKey
     * @return a base 64 encoded AES string.
     */
    public static String AesKeyToString(SecretKey aesKey) {
        return Base64.encodeToString(aesKey.getEncoded(), BASE64_FLAGS);
    }

    /**
     * An aes key derived from a base64 encoded key. This does not generate the
     * key. It's not random or a PBE key.
     * @param aesKeyStr a base64 encoded AES key.
     * @return an AES key suitable for other functions.
     */
    public static SecretKey AesKeyFromString(String aesKeyStr) {
        byte[] aesKeyBytes = Base64.decode(aesKeyStr, BASE64_FLAGS);
        return new SecretKeySpec(aesKeyBytes, 0, aesKeyBytes.length, CIPHER);
    }

    /**
     * A function that generates a random AES key and prints out exceptions but doesn't
     * throw them since none should be encountered. If they are encountered, the return
     * value is null.
     * @return The AES key.
     */
    public static SecretKey generateAesKey() {
        SecretKey key = null;
        try {
            key = generateAesKeyWithExceptions();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return key;
    }

    /**
     * A function that generates an AES key and throws exceptions
     * @return THe AES key
     * @throws NoSuchAlgorithmException This shouldn't happen since it's hard coded.
     */
    public static SecretKey generateAesKeyWithExceptions() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(CIPHER);
        //No need to provide a SecureRandom or set a seed since that will happen automatically.
        keyGen.init(AES_KEY_LENGTH);
        return keyGen.generateKey();
    }

    /**
     * Creates a random Initialization Vector (IV) of IV_LENGTH.
     * @return The byte array of this IV
     * @throws NoSuchAlgorithmException Shouldn't happen since it's hard coded.
     * @throws NoSuchProviderException Shouldn't happen since it's hard coded.
     */
    public static byte[] generateIvWithExceptions() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        return iv;
    }


    /* -----------------------------------------------------------------
    Encryption
    ----------------------------------------------------------------- */

    /**
     * Generates a random IV and encrypts this plain text with the given key.
     * Suitable for decrypting with aesDecryptToString.
     * Does not throw exception as with aesEncrypt since most of the related
     * variables are hard coded.
     * @param plaintext The text that will be encrypted
     * @param secretKey The AES key to do the encryption
     * @return a tuple of the IV and the crypto text.
     */
    public static CipherTextAndIV aesEncryptFromString(String plaintext, SecretKey secretKey) {
        return aesEncrypt(plaintext.getBytes(), secretKey);
    }

    /**
     * Generates a random IV and encrypts this plain text with the given key.
     * Does not throw exception as with aesEncrypt since most of the related
     * variables are hard coded.
     * @param plaintext The text that will be encrypted
     * @param secretKey The AES key to do the encryption
     * @return a tuple of the IV and the crypto text.
     */
    public static CipherTextAndIV aesEncrypt(byte[] plaintext, SecretKey secretKey) {
        CipherTextAndIV civ = null;
        try {
            civ = aesEncryptWithExceptions(plaintext, secretKey);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return civ;
    }

    /**
     * Generates a random IV and encrypts this plain text with the given key.
     * Throws exceptions when encountered.
     * @param plaintext The text that will be encrypted
     * @param secretKey The AES key to do the encryption
     * @return a tuple of the IV and the crypto text.
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static CipherTextAndIV aesEncryptWithExceptions(byte[] plaintext, SecretKey secretKey)
            throws NoSuchProviderException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv = generateIvWithExceptions();
        Cipher aesCipherForEncryption = Cipher.getInstance(CIPHER_TRANSFORMATION);
        aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, secretKey,
                new IvParameterSpec(iv));

        /* Now we get back the IV that will actually be used. Some Android versions
        do funny stuff w/ the IV, so this is to work around bugs: */
        iv = aesCipherForEncryption.getIV();
        byte[] byteCipherText = aesCipherForEncryption
                .doFinal(plaintext);
        return new CipherTextAndIV (byteCipherText, iv);
    }


    /* -----------------------------------------------------------------
    Decryption
    ----------------------------------------------------------------- */

    /**
     * AES CBC decrypt. Suitable for decrypting something encrypted by aesEncryptFromString
     * Does not throw exception as with aesDecrypt since most of the related
     * variables are hard coded.
     * @param civ The cipher text and IV
     * @param secretKey The AES key
     * @return A string derived from the decypted bytes (not base64 encoded)
     */
    public static String aesDecryptToString (CipherTextAndIV civ, SecretKey secretKey) {
        return new String(aesDecrypt(civ, secretKey));
    }

    /**
     * AES CBC decrypt.
     * Does not throw exception as with aesDecrypt since most of the related
     * variables are hard coded.
     * @param civ the cipher text and iv
     * @param secretKey the AES key
     * @return The raw decrypted bytes
     */
    public static byte[] aesDecrypt (CipherTextAndIV civ, SecretKey secretKey) {
        byte[] decryptedText = null;
        try {
            decryptedText = aesDecryptWithExceptions(civ, secretKey);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return decryptedText;
    }

    /**
     * AES CBC decrypt. Throws exceptions when encountered.
     * @param civ the cipher text and iv
     * @param secretKey the AES key
     * @return The raw decrypted bytes
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] aesDecryptWithExceptions (CipherTextAndIV civ, SecretKey secretKey)
            throws InvalidAlgorithmParameterException, InvalidKeyException,
            NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException,
            IllegalBlockSizeException {
        Cipher aesCipherForDecryption = Cipher.getInstance(CIPHER_TRANSFORMATION);
        aesCipherForDecryption.init(Cipher.DECRYPT_MODE, secretKey,
                new IvParameterSpec(civ.iv));
        return aesCipherForDecryption.doFinal(civ.cipherText);
    }
}
