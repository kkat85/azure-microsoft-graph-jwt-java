package jwttoken;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.codec.DecoderException;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class GenerateJWTToken {
	
	public static String generateJWTTokenWithRS256Sign(String clientId, String audience, String certPath, String certPassword, long expirationIntervalInMin) 
			throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, DecoderException {
		
		String jwtToken = null;
		
		long validFrominMilliSec = System.currentTimeMillis();
		String validFrom = String.valueOf(validFrominMilliSec).substring(0, String.valueOf(validFrominMilliSec).length()-3);

		long tokenExpTimeToAddInMilliSec = 60 * expirationIntervalInMin * 1000; // 1 hour
		long validToinMilliSec = validFrominMilliSec + tokenExpTimeToAddInMilliSec;
		String validTo = String.valueOf(validToinMilliSec).substring(0, String.valueOf(validToinMilliSec).length()-3);;

		String certSHA1HashValue = GetHexBinaryFromCertificate.getHexBinaryFromCertificate(certPath, certPassword); //get Hex from Cert

		Map<String, Object> header = new HashMap<String, Object>(); //Add x5t header
		header.put("x5t", ConvertHexToString.convertHexToString(certSHA1HashValue));
		
		Map<String, Object> claims = new HashMap<String, Object>(); //Add payload
		claims.put("aud", audience);
		claims.put("exp", validTo);
		claims.put("iss", clientId);
		claims.put("jti", UUID.randomUUID());
		claims.put("nbf", validFrom);
		claims.put("sub", clientId);
		
		Key key = GetKeyFromCertificate.getKeyFromCertUsingAliasName(certPath, certPassword);

		if(key != null) {
			jwtToken = Jwts.builder()
			           .setHeader(header)
			           .setClaims(claims)
					   .signWith(SignatureAlgorithm.RS256, key)			   
					   .compact();
		}

//		System.out.println(jwtToken);
		
		return jwtToken;
		
	}
}
