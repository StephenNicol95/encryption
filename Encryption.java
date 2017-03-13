package encryption;

import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {
	private static Encryption INSTANCE = new Encryption();
	private static final Base64.Encoder BASE64ENCODER = Base64.getEncoder();
	private static final Base64.Decoder BASE64DECODER = Base64.getDecoder();
	private final String XORENCRYPTIONKEY = "A%9h5ZWRyvH3KPs6m@";
	private final String AESENCRYPTIONKEY = "cE7zrSvD*X4nkj7x";
	private static SecretKeySpec secret;
	
	public static Encryption getInstance() {
		return INSTANCE;
	}
	
	public Encryption() {
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(AESENCRYPTIONKEY.toCharArray(), AESENCRYPTIONKEY.getBytes(), 65535, 128);
			SecretKey key = factory.generateSecret(spec);
			secret = new SecretKeySpec(key.getEncoded(), "AES");
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public byte[] encrypt(String LEADERBOARD) {
		return aesEncrypt(xorEncryption(LEADERBOARD));
	}
	
	public String decrypt(byte[] LEADERBOARD) {
		return xorEncryption(aesDecrypt(LEADERBOARD));
	}
	
	public String xorEncryption(String LEADERBOARD) {
		String toReturn = "";
		for(int i = 0; i < LEADERBOARD.length(); i++) {
			toReturn += (char) (LEADERBOARD.charAt(i) ^ XORENCRYPTIONKEY.charAt(i % XORENCRYPTIONKEY.length()));
		}
		return toReturn;
	}
	
	private byte[] aesEncrypt(String LEADERBOARD) {
		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secret);
			return cipher.doFinal(LEADERBOARD.getBytes());
		} catch(Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	private String aesDecrypt(byte[] LEADERBOARD) {
		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secret);
			return new String(cipher.doFinal(LEADERBOARD));
		} catch(Exception e) {
			e.printStackTrace();
		}
		return "";
	}
	
	public static void main(String[] args) {
		String test = "test";
		Encryption encrypt = Encryption.getInstance();
		
		//test xor encryption
		System.out.println(test);
		System.out.println(encrypt.xorEncryption(test));
		System.out.println(encrypt.xorEncryption(encrypt.xorEncryption(test)));
		System.out.println("");
		
		//test aesEncrypt and aesDecrypt
		System.out.println(test);
		System.out.println(encrypt.aesEncrypt(test));
		System.out.println(encrypt.aesDecrypt(encrypt.aesEncrypt(test)));
		System.out.println("");
		
		//test both AES and XOR
		System.out.println(test);
		System.out.println(encrypt.aesEncrypt(encrypt.xorEncryption(test)));
		System.out.println(encrypt.xorEncryption(encrypt.aesDecrypt(encrypt.aesEncrypt(encrypt.xorEncryption(test)))));
		System.out.println("");
		
		//Base64 Tests
		System.out.println(test);
		System.out.println(BASE64ENCODER.encode(test.getBytes()));
		System.out.println(new String(BASE64DECODER.decode(BASE64ENCODER.encode(test.getBytes()))));
		System.out.println(BASE64ENCODER.encode(encrypt.encrypt(test)));
		System.out.println(encrypt.decrypt(BASE64DECODER.decode(BASE64ENCODER.encode(encrypt.encrypt(test)))));
	}
}
