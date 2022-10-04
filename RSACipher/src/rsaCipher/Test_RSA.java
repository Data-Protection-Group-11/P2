package rsaCipher;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class Test_RSA {
	
	public static void getResult(Boolean isEqual){
		if(isEqual){
			System.out.println("VERIFIED");
		} else {
			System.out.println("NOT VERIFIED");
		}
	}

	public static void main(String[] args) throws Exception {
		RSALibrary r = new RSALibrary();
		r.generateKeys();
		
		/* Read  public key*/
		Path path = Paths.get("./data/public.key");
		byte[] bytes = Files.readAllBytes(path);
		//Public key is stored in x509 format
		X509EncodedKeySpec keyspec = new X509EncodedKeySpec(bytes);
		KeyFactory keyfactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyfactory.generatePublic(keyspec);
		
		/* Read private key */
		path = Paths.get("./data/private.key");
		byte[] bytes2 = Files.readAllBytes(path);
		//Private key is stored in PKCS8 format
		PKCS8EncodedKeySpec keyspec2 = new PKCS8EncodedKeySpec(bytes2);
		KeyFactory keyfactory2 = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyfactory2.generatePrivate(keyspec2);
		

		//TEST cipher and decipher
		path = Paths.get("./data/test0.txt");
		String txt = new String();
		
		try {
			txt = Files.readString(path);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		byte[] txtBytes = txt.getBytes(); 
		byte[] txtEncrypt = r.encrypt(txtBytes, publicKey);

		System.out.println("========= Text already ciphered: =========");
		String txtEncryptString = new String(txtEncrypt);
		System.out.println(txtEncryptString);

		byte[] txtDecrypt = r.decrypt(txtEncrypt, privateKey);
		
		System.out.println("\n\n========= Deciphered text: =========");		
		String txtFinal = new String(txtDecrypt);
		System.out.println(txtFinal);

		//TEST sign and verify
	
		path = Paths.get("./data/test1.txt");
		String txtToSign2 = new String();
		
		try {
			txtToSign2 = Files.readString(path);
		} catch (IOException e) {
			e.printStackTrace();
		}

		byte[] txtBytes2 = txt.getBytes();
		byte[] txtSign = r.sign(txtBytes2, privateKey);

		System.out.println("========= Text signed =========");
		String txtSignString = new String(txtSign);
		System.out.println(txtSignString);

		Boolean isEqual = r.verify(txtBytes2, txtSign, publicKey);
		
		System.out.println("\n\n========= Verify sign: =========");	
		getResult(isEqual);


		System.out.println("Check integrity with txtToSign2");
		Boolean isEqual2 = r.verify(txtToSign2.getBytes(), txtSign, publicKey);
		getResult(isEqual2);
	}

}
