package jwttoken;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class ConvertHexToString {

	public static String convertHexToString(String hex) throws DecoderException {
		
		String result = null;
		
		byte[] bytes = Hex.decodeHex(hex);
		result = Base64.encodeBase64String(bytes);
		
		return result;
	}
}
