package jwttoken;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.apache.commons.codec.DecoderException;
import org.junit.Test;

public class GenerateJWTTokenTest {

	@Test
	public void testGenerateJWTTokenWithRS256Sign() {

		final String clientId = "97e0a5b7-d745-40b6-94fe-5f77d35c6e05"; //sample client id
		final String audience = "https://login.microsoftonline.com/d76eeee8-58e1-2313-b604-5f77d34004/v2.0"; //sample audience with tenantid
		final String certPath = "C:\\certs\\Email-cert.pfx"; //can be jks cert
		final String certPassword = "pass@word1"; //if jks cert, use jks cert pass
		final long expirationIntervalInMin = 60;
		
		String jwtValue = null;
		try {
			jwtValue = GenerateJWTToken.generateJWTTokenWithRS256Sign(clientId, audience, certPath, certPassword, expirationIntervalInMin);
			System.out.println(jwtValue);
			
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
				| IOException | DecoderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		assertNotNull("jwt token generation failed", jwtValue);

	}

}
