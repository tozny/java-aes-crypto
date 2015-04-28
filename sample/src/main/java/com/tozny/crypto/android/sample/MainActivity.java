package com.tozny.crypto.android.sample;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import  com.tozny.crypto.android.AesCbcWithIntegrity;

import static com.tozny.crypto.android.AesCbcWithIntegrity.decryptString;
import static com.tozny.crypto.android.AesCbcWithIntegrity.encrypt;
import static com.tozny.crypto.android.AesCbcWithIntegrity.generateKey;
import static com.tozny.crypto.android.AesCbcWithIntegrity.generateKeyFromPassword;
import static com.tozny.crypto.android.AesCbcWithIntegrity.generateSalt;
import static com.tozny.crypto.android.AesCbcWithIntegrity.keyString;
import static com.tozny.crypto.android.AesCbcWithIntegrity.keys;
import static com.tozny.crypto.android.AesCbcWithIntegrity.saltString;

/**
 * Sample shows password based key gen
 */
public class MainActivity extends Activity {
    public static final String TAG = "Tozny";

    private static boolean PASSWORD_BASED_KEY = true;
    private static String EXAMPLE_PASSWORD = "LeighHunt";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            AesCbcWithIntegrity.SecretKeys key;
            if (PASSWORD_BASED_KEY) {//example for password based keys
                String salt = saltString(generateSalt());
                //If you generated the key from a password, you can store the salt and not the key.
                Log.i(TAG, "Salt: " + salt);
                key = generateKeyFromPassword(EXAMPLE_PASSWORD, salt);
            } else {
                key = generateKey();
                //Note: If you are generating a random key, you'll probably be storing it somewhere
            }

            // The encryption / storage & display:

            String keyStr = keyString(key);
            key = null; //Pretend to throw that away so we can demonstrate converting it from str

            String textToEncrypt = "We, the Fairies, blithe and antic,\n" +
                    "Of dimensions not gigantic,\n" +
                    "Though the moonshine mostly keep us,\n" +
                    "Oft in orchards frisk and peep us. ";
            Log.i(TAG, "Before encryption: " + textToEncrypt);

            // Read from storage & decrypt
            key = keys(keyStr); // alternately, regenerate the key from password/salt.
            AesCbcWithIntegrity.CipherTextIvMac civ = encrypt(textToEncrypt, key);
            Log.i(TAG, "Encrypted: " + civ.toString());

            String decryptedText = decryptString(civ, key);
            Log.i(TAG, "Decrypted: " + decryptedText);
            //Note: "String.equals" is not a constant-time check, which can sometimes be problematic.
            Log.i(TAG, "Do they equal: " + textToEncrypt.equals(decryptedText));
        } catch (GeneralSecurityException e) {
            Log.e(TAG, "GeneralSecurityException", e);
        } catch (UnsupportedEncodingException e) {
            Log.e(TAG, "UnsupportedEncodingException", e);
        }

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
