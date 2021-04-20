package jwttoken;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

public class GetKeyFromCertificate {
	
	public static Key getKeyFromCertUsingAliasName(String certPath, String certPass) 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException {
		
		File file = new File(certPath);
		KeyStore ks  = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(file), certPass.toCharArray()); //Load certificate

		Enumeration<String> aliasNames = ks.aliases();
		String alias = (String) aliasNames.nextElement(); //get Alias Name
//		System.out.println(alias);

		Key key = ks.getKey(alias, certPass.toCharArray()); //get Key using Alias name
//		System.out.println("key value is :" + key);

		return key;
	}

}
