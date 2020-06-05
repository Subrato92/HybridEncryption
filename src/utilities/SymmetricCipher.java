package utilities;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class SymmetricCipher {

	public static byte[] encrypt(byte[] msg, String algo, SecretKey key) {

		Cipher cipher;
		byte[] encryptedMsg = null;
		try {

			cipher = Cipher.getInstance(algo);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			encryptedMsg = cipher.doFinal(msg);

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return encryptedMsg;
	}

	public static byte[] decrypt(byte[] encryptedMsg, String algo, SecretKey key) {

		Cipher cipher;
		byte[] msg = null;
		try {

			cipher = Cipher.getInstance(algo);
			cipher.init(Cipher.DECRYPT_MODE, key);
			msg = cipher.doFinal(encryptedMsg);

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return msg;
	}

}
