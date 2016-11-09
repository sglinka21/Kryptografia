import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;

public class Krypto {
	
	private static final Charset CHARSET = Charset.forName("UTF-8");
	//private static final String PADDING = "PKCS5Padding";
	private static final String PADDING = "NoPadding";
	String key, str;
	//byte[] cipherBytes;

	SecretKey aesKey;
	byte[] keyBytes;

	byte[] iv;
	Cipher cipher;
	IvParameterSpec ivParam;

	String ciph;
	String plainText;

	byte[][] ciphersBytes;
	IvParameterSpec[] ivParams;

	Krypto() throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeySpecException {
		cipher = Cipher.getInstance("AES/CBC/" + PADDING);
		ciphersBytes = new byte[2][];
		ivParams = new IvParameterSpec[2];

		

	}

	void setIv(String iv) {
		this.iv = DatatypeConverter.parseHexBinary(iv);
		ivParam = new IvParameterSpec(this.iv);
	}

	String decrypt(String key, int nr) {
		plainText = "";
		try {
			keyBytes = DatatypeConverter.parseHexBinary(key);
			aesKey = new SecretKeySpec(keyBytes, "AES");
			cipher.init(Cipher.DECRYPT_MODE, aesKey, ivParams[nr]);
			plainText = new String(cipher.doFinal(ciphersBytes[nr]), CHARSET);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return plainText;
	}

	void zad1() throws FileNotFoundException, UnsupportedEncodingException {
		String keySuffix = "a21bca01768a0c31e0136f1f5a0e1f0d8900f3afced61efd89b47436";
		this.setIv("1769cae4a6813c193ac786128eaf4a04");
		ivParams[0] = ivParam;
		this.setIv("c04db0c87c3a475bc49c76bbde388e03");
		ivParams[1] = ivParam;

		ciph = "nK7CHc8LJ9oF1BRTCKlVwVOjDyZp8Cz7dzVI8E30koIHP5C8iLYsy0OMXSJZCykMCBQ9bQ7Sn+tun+glJYQfZA==";
		ciphersBytes[0] = DatatypeConverter.parseBase64Binary(ciph);
		ciphersBytes[0] = Arrays.copyOfRange(ciphersBytes[0], 0, 16);
		ciph = "ItQZ5Rd+e39D+2p0mXheCUaC2jcX2gzqa8WJp6kPCifZwIFbUb217MW8MPymBRaF5AP0wxBFAUj1po6aHs6omA==";
		ciphersBytes[1] = DatatypeConverter.parseBase64Binary(ciph);
		ciphersBytes[1] = Arrays.copyOfRange(ciphersBytes[1], 0, 16);
		
		String plain = null;
		String plain1 = null;
		long tStart = System.currentTimeMillis();
		String nameFile = "zad1";
		PrintWriter writer = new PrintWriter(nameFile + ".txt", CHARSET.toString());
		for (int i0 = 0; i0 < 16; i0++) {
			for (int i1 = 0; i1 < 16; i1++) {
				for (int i2 = 0; i2 < 16; i2++) {
					for (int i3 = 0; i3 < 16; i3++) {
						for (int i4 = 0; i4 < 16; i4++) {
							for (int i5 = 0; i5 < 16; i5++) {
								for (int i6 = 0; i6 < 16; i6++) {
									for (int i7 = 0; i7 < 16; i7++) {
										String correctKey =  
												  Integer.toHexString(i0) + Integer.toHexString(i1)
												+ Integer.toHexString(i2) + Integer.toHexString(i3)
												+ Integer.toHexString(i4) + Integer.toHexString(i5)
												+ Integer.toHexString(i6) + Integer.toHexString(i7) 
												+ keySuffix;
										plain = this.decrypt(correctKey, 0);
										plain1 = this.decrypt(correctKey, 1);
										
										// sprawdzanie wyniku
										if (plain.equals(plain1)) {
											System.out.println(correctKey + "\t" + plain);
											writer.println(correctKey + "\t" + plain);
											writer.flush();
										}
									}
								}
							}
						}
					}
				}
				System.out.print((100.0 / 16 * (i0)) + (100.0 / 256 * (i1 + 1)) + "%\t---\t");
				System.out.println(((System.currentTimeMillis() - tStart) / 1000.0) + " sek");
			}
		}
		writer.close();
	}


	
	public static void main(String[] args) throws Exception {
		Krypto kryp = new Krypto();
		kryp.zad1();
		//test();
	}

	static void test() throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		String iv = "1769cae4a6813c193ac786128eaf4a04";
		String key = "d15d61c9a21bca01768a0c31e0136f1f5a0e1f0d8900f3afced61efd89b47436";
		String cipherText = "nK7CHc8LJ9oF1BRTCKlVwVOjDyZp8Cz7dzVI8E30koIHP5C8iLYsy0OMXSJZCykMCBQ9bQ7Sn+tun+glJYQfZA==";
		
		SecretKey aesKey = new SecretKeySpec(DatatypeConverter.parseHexBinary(key), "AES");
		byte [] ivBytes = DatatypeConverter.parseHexBinary(iv);
		
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(ivBytes));
		byte[] result = cipher.doFinal(DatatypeConverter.parseBase64Binary(cipherText));
		System.out.println(new String(result, "UTF-8"));
	}
}
