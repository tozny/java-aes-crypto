package com.tozny.crypto.basicaescbc;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;

import javax.crypto.SecretKey;

import com.tozny.crypto.basicaescbc.R;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import static com.tozny.crypto.basicaescbc.AesCbcPadding.generateKeyFromPassword;
import static com.tozny.crypto.basicaescbc.AesCbcPadding.generateSalt;
import static com.tozny.crypto.basicaescbc.AesCbcPadding.key;
import static com.tozny.crypto.basicaescbc.AesCbcPadding.keyString;
import static com.tozny.crypto.basicaescbc.AesCbcPadding.decrypt;
import static com.tozny.crypto.basicaescbc.AesCbcPadding.decryptString;
import static com.tozny.crypto.basicaescbc.AesCbcPadding.encrypt;
import static com.tozny.crypto.basicaescbc.AesCbcPadding.generateKey;
import static com.tozny.crypto.basicaescbc.AesCbcPadding.saltString;


public class MyActivity extends Activity {
    private static boolean PASSWORD_BASED_KEY = true;
    private static String EXAMPLE_PASSWORD = "LeighHunt";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_my);

        try {
            SecretKey key;
            if (PASSWORD_BASED_KEY) {//example for password based keys
                String salt = saltString(generateSalt());
                // Store the salt; it's not a secret, don't worry.
                Log.i("Tozny", "Salt: " + salt);
                key = generateKeyFromPassword(EXAMPLE_PASSWORD, salt);
            } else {
                key = generateKey();
            }

            // The encryption / storage & display:

            String keyStr = keyString(key);
            key = null; //Pretend to throw that away
            Log.i("Tozny", "Key: " + keyStr);

            String textToEncrypt = "We, the Fairies, blithe and antic,\n" +
                    "Of dimensions not gigantic,\n" +
                    "Though the moonshine mostly keep us,\n" +
                    "Oft in orchards frisk and peep us. ";
            Log.i("Tozny", "Before encryption: " + textToEncrypt);

            // Read from storage & decrypt
            key = key(keyStr); // alternately, regenerate the key from password/salt.
            AesCbcPadding.CipherTextAndIv civ = encrypt(textToEncrypt, key);
            Log.i("Tozny", "Encrypted: " + civ.toString());

            String decryptedText = decryptString(civ, key);
            Log.i("Tozny", "Decrypted: " + decryptedText);
            //Note: "String.equals" is not a constant-time check, which can sometimes be problematic.
            Log.i("Tozny", "Do they equal: " + textToEncrypt.equals(decryptedText));
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.my, menu);
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
