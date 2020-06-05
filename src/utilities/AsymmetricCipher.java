package utilities;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class AsymmetricCipher {
	
	public static byte[] encrypt(byte[] msg, String algo, PublicKey pubKey) {
		Cipher cipher;
		byte[] encryptedMsg = null;
		try {
			cipher = Cipher.getInstance(algo);
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			encryptedMsg = cipher.doFinal(msg);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return encryptedMsg;		
	}
	
	public static byte[] decrypt(byte[] encryptedMsg, String algo, PrivateKey pvtKey) {
		Cipher cipher;
		byte[] msg = null;
		try {
			cipher = Cipher.getInstance(algo);
			cipher.init(Cipher.DECRYPT_MODE, pvtKey);
			msg = cipher.doFinal(encryptedMsg);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return msg;		
	}

}
