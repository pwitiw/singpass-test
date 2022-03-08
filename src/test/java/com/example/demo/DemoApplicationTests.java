//package com.example.demo;
//
//import org.junit.jupiter.api.Test;
//import org.springframework.boot.test.context.SpringBootTest;
//
//import java.io.FileInputStream;
//import java.security.KeyStore;
//import java.security.PrivateKey;
//import java.security.Signature;
//
//class DemoApplicationTests {
//
//	@Test
//	void testSecret() {
//		var baseString = "POST&https://test.api.myinfo.gov.sg/sgverify/v2/token&app_id=STG2-SGVERIFY-SELF-TEST&client_id=STG2-SGVERIFY-SELF-TEST&client_secret=WnBdUYAftjB8gLt4cjl1N01XulG1q7fn&code=0b43b47773205a7779d5a572fd3ae841820a8eaa&grant_type=authorization_code&nonce=2d897d4f-5f4f-48ed-a71b-ecc95324c7b9&redirect_uri=http://localhost:3001/callback&signature_method=RS256&state=DEMOKIOSK8&timestamp=1645516824146";
//		KeyStore keyStore = KeyStore.getInstance("PKCS12");
//		// TODO zmienic path
//		keyStore.load(new FileInputStream("C:\\Users\\e-pkww\\Downloads\\demo\\src\\main\\resources\\your-sample-app-certificate.p12"), "DemoApp".toCharArray());
//		return (PrivateKey) keyStore.getKey("1", "DemoApp".toCharArray());
//		Signature sig = Signature.getInstance("SHA256withRSA");
//		sig.initSign(privateKey);
//		sig.update(data);
//		byte[] digitalSignature = sig.sign();
//
//
//
//	}
//
//}
