package jwttoken;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.xml.bind.DatatypeConverter;

public class GetHexBinaryFromCertificate {
	
	public static String getHexBinaryFromCertificate(String certPath, String certPass) 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		
		String result = null;
		
		File file = new File(certPath);
		KeyStore ks  = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(file), certPass.toCharArray()); //Load certificate

		Enumeration<String> aliasNames = ks.aliases();
		String alias = (String) aliasNames.nextElement(); //get Alias Name
//		System.out.println(alias);

		X509Certificate cert = (X509Certificate) ks.getCertificate(alias); //get Certificate
		
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		
		byte[] inputCert = cert.getEncoded();
		md.update(inputCert); 
		
		byte[] digest = md.digest();
		result = DatatypeConverter.printHexBinary(digest);
//		System.out.println(result);
		
		return result;
	}

}
