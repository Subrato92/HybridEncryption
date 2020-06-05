import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import utilities.AsymmetricCipher;
import utilities.SymmetricCipher;

public class Decrypter {

	public static File decryptionFlow(String path, PrivateKey pvtKey, String secretKeyAlgo, String symmetricAlgo, String asymmetricAlgo) throws IOException {

		File inFile = new File(path);
		String[] contents = extractDataElements(inFile);

		System.out.println("Content Count: "+contents.length);
		
		for (int i = 0; i < contents.length; i++) {
			contents[i] = filterNewlineChars(contents[i]);
		}
		
		System.out.println("\n@Base64 encoded Encrypted Secret Key String: ");
		System.out.println(contents[0]);
		System.out.println("\n@Base64 encoded Encrypted Data String: ");
		System.out.println(contents[1]);
		
		Base64.Decoder decoder = Base64.getDecoder();		
		
		byte[] encSecretKeyByte = decoder.decode(contents[0]);
		System.out.println("\n@Enc SecretKey");
		System.out.println(Arrays.toString(encSecretKeyByte));
		
		byte[] secretKeyBytes = AsymmetricCipher.decrypt(encSecretKeyByte, asymmetricAlgo, pvtKey);		
		System.out.println("\n@Secret Key Bytes: ");
		System.out.println(Arrays.toString(secretKeyBytes));
		
		SecretKey secretKey = new SecretKeySpec(secretKeyBytes, 0, secretKeyBytes.length, secretKeyAlgo);

		ArrayList<byte[]> dataList = new ArrayList<byte[]>();
		for (int i = 1; i < contents.length; i++) {
			byte[] encStrByte = decoder.decode(contents[i]);
			System.out.println("\n@Encrypted Data Bytes: ");
			System.out.println(Arrays.toString(encStrByte));
			
			byte[] messageByte = SymmetricCipher.decrypt(encStrByte, symmetricAlgo, secretKey);
			System.out.println("\n@Data Bytes: ");
			System.out.println(Arrays.toString(messageByte));
			
			dataList.add(messageByte);
			contents[i] = new String(messageByte, StandardCharsets.UTF_8);
		}
		
		int lastIndx = inFile.getPath().lastIndexOf(".");
		String outpath = inFile.getPath().substring(0, lastIndx);

		lastIndx = outpath.lastIndexOf(".");
		outpath = outpath.substring(0, lastIndx).concat(".dat");
		outpath = outpath.substring(0, lastIndx).concat(".dat");
		
		File nwFile = new File(outpath);
		OutputStream os = new FileOutputStream(nwFile);
		for (byte[] data : dataList) {
			os.write(data);
		}
		os.close();

		return nwFile;
	}

	private static String[] extractDataElements(File file) {

		String[] dataArr = null;

		FileReader reader;
		BufferedReader bufReader;
		try {

			char nwLine = '\n';
			char cr = '\r';

			reader = new FileReader(file);
			bufReader = new BufferedReader(reader);
			
			
			//Extracting the Encrypted Secret Key
			String encSecretKey = bufReader.readLine();
			
			StringBuilder sb = new StringBuilder();
			char[] buffer = new char[10]; 
			int nChars = bufReader.read(buffer);
			while (nChars>0) {
				
				for(int i=0; i<nChars; i++) {
					sb.append(buffer[i]);	
				}
				
				nChars = bufReader.read(buffer);				
			}
			
			dataArr = new String[2]; 
			dataArr[0] = encSecretKey;
			dataArr[1] = sb.toString();

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return dataArr;
	}

	private static String filterNewlineChars(String data) {

		if (data == null) {
			return null;
		}

		char carriageReturn = '\r';
		char newLine = '\n';
		int length = data.length();
		int indx = 0;

		// Checking nextLine chars at the start of the line
		while (indx < length && (data.charAt(indx) == carriageReturn || data.charAt(indx) == newLine)) {
			indx++;
		}

		int startIndx = indx;		
		indx = length-1;
		// Checking nextLine Chars at the end of the line
		while (indx >= startIndx && (data.charAt(indx) == carriageReturn || data.charAt(indx) == newLine)) {
			indx--;
		}
		int endIndx = indx+1;

		String cleanData = data.substring(startIndx, endIndx);
		System.out.println("AcLength:" + data.length() + ", ModLength:" + cleanData.length());

		return cleanData;
	}
	
}
