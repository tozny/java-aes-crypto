package com.tozny.aes_crypto_sample;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import com.tozny.aeswithintegritysample.R;
import com.tozny.crypto.android.AesCbcWithIntegrity;
import static com.tozny.crypto.android.AesCbcWithIntegrity.*;

public class MainActivity extends AppCompatActivity {

    public static final String TAG = "Tozny";

    private static boolean PASSWORD_BASED_KEY = true;
    private static String EXAMPLE_PASSWORD = "always use passphrases for passwords wherever possible!";

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

            String textToEncrypt = "Testing shows the presence, not the absence of bugs.\n\n  Edsger W. Dijkstra";
            Log.i(TAG, "Before encryption: " + textToEncrypt);

            // Read from storage & decrypt
            key = keys(keyStr); // alternately, regenerate the key from password/salt.
            AesCbcWithIntegrity.CipherTextIvMac civ = encrypt(textToEncrypt, key);
            Log.i(TAG, "Encrypted: " + civ.toString());

            String decryptedText = decryptString(civ, key);
            Log.i(TAG, "Decrypted: " + decryptedText);
            //Note: "String.equals" is not a constant-time check, which can sometimes be problematic.
            Log.i(TAG, "Do they equal: " + textToEncrypt.equals(decryptedText));

            TextView t = (TextView) findViewById(R.id.textView);
            t.setText(decryptedText);
        } catch (GeneralSecurityException e) {
            Log.e(TAG, "GeneralSecurityException", e);
        } catch (UnsupportedEncodingException e) {
            Log.e(TAG, "UnsupportedEncodingException", e);
        }

    }
}
