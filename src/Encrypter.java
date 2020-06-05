import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import utilities.AsymmetricCipher;
import utilities.SymmetricCipher;

public class Encrypter {

	public static File encryptionFlow(String path, PublicKey publicKey, int secretKeySize, String secretKeyAlgo, String symmetricAlgo, String asymmetricAlgo) {

		// Secret Key Generation
		KeyGenerator keyGenerator;
		File encryptedFile = null;
		try {			
			File file = new File(path);
			
			// AES 128
			keyGenerator = KeyGenerator.getInstance(secretKeyAlgo);
			keyGenerator.init(secretKeySize);
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] secretkeyByte = secretKey.getEncoded();
			System.out.println("\n@EncFlow: Original Secret Key");
			System.out.println(Arrays.toString(secretkeyByte));
			
			// Reading content
			FileReader reader = new FileReader(file);
			BufferedReader buffReader = new BufferedReader(reader);
			
			char[] buffer = new char[100];
			int nChar = buffReader.read(buffer);
			StringBuilder sb = new StringBuilder();
			while (nChar>0) {
				for(int i=0; i<nChar; i++) {
					sb.append(buffer[i]);
				}
				
				nChar = buffReader.read(buffer);
			}
			String content = sb.toString();
			byte[] contentBytes = content.getBytes(StandardCharsets.UTF_8);
			System.out.println("\n@Content Bytes");
			System.out.println(Arrays.toString(contentBytes));
			byte[] encDataBytes = SymmetricCipher.encrypt(contentBytes, symmetricAlgo, secretKey);
			System.out.println("\n@Encrypted Content Bytes");
			System.out.println(Arrays.toString(encDataBytes));
			byte[] encSecretkey = AsymmetricCipher.encrypt(secretkeyByte, asymmetricAlgo, publicKey);
			System.out.println("\n@Encrypted Secret Key : ");
			System.out.println(Arrays.toString(encSecretkey));
			
			Base64.Encoder encoder = Base64.getEncoder();
			
			byte[] base64EncSecKey = encoder.encode(encSecretkey);
			byte[] base64EncData = encoder.encode(encDataBytes);

			String encSecretkeyString = new String(base64EncSecKey, StandardCharsets.UTF_8);
			String encDataString = new String(base64EncData, StandardCharsets.UTF_8);
			System.out.println("\n@Encrypted Secret Key String: ");
			System.out.println(encSecretkeyString);
			System.out.println("\n@Encrypted Data String: ");
			System.out.println(encDataString);
			// FileContent
			sb = new StringBuilder();
			sb.append(encSecretkeyString).append(System.lineSeparator()).append(encDataString);

			// Creation of encrypted file
			String encFilePath = file.getPath().concat(".enc");

			encryptedFile = new File(encFilePath);
			FileWriter writer;
			writer = new FileWriter(encryptedFile);
			BufferedWriter bufWriter = new BufferedWriter(writer);
			bufWriter.write(sb.toString());
			bufWriter.close();

		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		return encryptedFile;
	}
}
