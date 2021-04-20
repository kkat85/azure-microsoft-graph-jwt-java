package jwttoken;

import static org.junit.Assert.*;

import org.apache.commons.codec.DecoderException;
import org.junit.Test;

public class ConvertHexToStringTest {

	@Test
	public void testConvertHexToString() {
		
		final String sampleHexValue = "84E05C1D98BCE3A5421D225B140B36E86A3D5534";
		final String expectedOutput = "hOBcHZi846VCHSJbFAs26Go9VTQ=";
		
		String result = null;
		try {
			result = ConvertHexToString.convertHexToString(sampleHexValue);
		} catch (DecoderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		assertEquals("success",expectedOutput, result);
	}

}
