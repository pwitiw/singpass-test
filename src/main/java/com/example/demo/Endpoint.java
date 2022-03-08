package com.example.demo;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import lombok.*;
import okhttp3.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.FileInputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Base64;
import java.util.Random;
import java.util.UUID;
import java.util.stream.StreamSupport;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
class SingpassAccessTokenResponse {
    @JsonProperty("access_token")
    private String accessToken;
}

@Builder
@Getter
class SingpassAccessTokenRequestBody {
    private final String grant_type;
    private final String code;
    private final String redirect_uri;
    private final String client_id;
    private final String client_secret;
    private final String state;

    String toJson() {
        return " {" +
                "grant_type: '" + grant_type + "'," +
                "code: '" + code + "'," +
                "redirect_uri: '" + redirect_uri + "'," +
                "client_id: '" + client_id + "'," +
                "client_secret: '" + client_secret + "'," +
                "state: '" + state + "'" +
                "}";
    }

    String postowe() {
        return String.format("grant_type=%s&code=%s&redirect_uri=%s&client_id=%s&client_secret=%s&state=%s",
                grant_type,
                code,
//                redirect_uri,
                "http%3A%2F%2Flocalhost%3A3001%2Fcallback",
                client_id,
                client_secret,
                state);
    }
}

@RequiredArgsConstructor
@Getter
@Builder
@ToString
class SingpassAuthHeader {
    private final long timestamp;
    private final long nonce;
    private final String appId;
    private final String signatureMethod;
    private final String signature;
    private final String accessToken;

    String toJson() {
        return "PKI_SIGN " +
                "timestamp=\"" + timestamp +
                "\",nonce=\"" + nonce +
                "\",app_id=\"" + appId +
                "\",signature_method=\"" + signatureMethod +
                "\",signature=\"" + signature +
                "\",Bearer " + accessToken;
    }
}

@RestController
@RequiredArgsConstructor
class Orrr {
    private static final String TOKEN_URL = "https://test.api.myinfo.gov.sg/sgverify/v2/token";
    private static final String PERSON_URL = "https://test.api.myinfo.gov.sg/sgverify/v2/person";
    //    private static final String TOKEN_URL = "https://sandbox.api.myinfo.gov.sg/sgverify/v2/token";
//    private static final String PERSON_URL = "https://sandbox.api.myinfo.gov.sg/sgverify/v2/person";
    private final ObjectMapper objectMapper;

    @GetMapping("/callback")
    @ResponseBody
    String test(@RequestParam String code, @RequestParam String state) throws Exception {
        var singpassTokenRequestBody = SingpassAccessTokenRequestBody.builder()
                .grant_type("authorization_code")
                .code(code)
                .state(state)
                .redirect_uri("http://localhost:3001/callback") // spr czyu mozna bez tego
                .client_id("STG2-SGVERIFY-SELF-TEST")
                .client_secret("WnBdUYAftjB8gLt4cjl1N01XulG1q7fn")
                .build();

        var authorizationHeaderApiCall = createPostAuthHeader(code, state).toJson();
        System.out.println("Header: " + authorizationHeaderApiCall);
        OkHttpClient client = new OkHttpClient.Builder()
                .build();
        var requestBody = okhttp3.RequestBody.create(singpassTokenRequestBody.postowe(), MediaType.parse("application/x-www-form-urlencoded"));
        Request request = new Request.Builder()
                .url(TOKEN_URL)
                .post(requestBody)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cache-Control", "no-cache")
                .header("Authorization", authorizationHeaderApiCall)
                .build();

        Call call = client.newCall(request);
        Response response = call.execute();
        var tokenResponseBody = response.body().string();
        var singpassResponse = objectMapper.readValue(tokenResponseBody, SingpassAccessTokenResponse.class);

        var chunks = singpassResponse.getAccessToken().split("\\.");
        var payload = new String(Base64.getDecoder().decode(chunks[1]));
        var json = new JSONObject(payload);
        var attributes = attributes(json.getJSONArray("scope"));
        var txnNo = UUID.randomUUID();
        var strParams = "client_id=" + singpassTokenRequestBody.getClient_id() +
                "&attributes=" + attributes +
                "&txnNo=" + txnNo;
        var url = PERSON_URL + "/" + json.get("sub");
        var fullPath = url + "?" + strParams;

        Request requestUserDetails = new Request.Builder()
                .url(fullPath)
                .get()
                .header("Cache-Control", "no-cache")
                .header("Authorization", createGetAuthHeader(url, attributes, singpassResponse.getAccessToken(), txnNo).toJson())
                .build();
        Response userDataResponse = client.newCall(requestUserDetails).execute();
        var encryptedUserData = userDataResponse.body().string();


//        PrivateKey privateKey = loadPrivateKey();
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
//
//        RSAPrivateKey privateRsaKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
//
//
//        EncryptedJWT jwt = EncryptedJWT.parse(encryptedUserData);
//        RSADecrypter decrypter = new RSADecrypter(privateRsaKey);
//        jwt.decrypt(decrypter);
        return encryptedUserData;
    }

    private String attributes(JSONArray scope) {
        return StreamSupport.stream(scope.spliterator(), false)
                .map(String::valueOf)
                .reduce((a, b) -> a + "," + b)
                .orElse("");
    }

    private static SingpassAuthHeader createGetAuthHeader(String url, String attributes, String accessToken, UUID txnNo) throws Exception {
        Random rand = SecureRandom.getInstance("SHA1PRNG");
        long nonce = rand.nextLong();
        long timestamp = System.currentTimeMillis();

        var baseString = generateBaseStringGet(url, nonce, timestamp, attributes, txnNo);
        String signature = sign(baseString);

        var authHeader = SingpassAuthHeader.builder()
                .appId("STG2-SGVERIFY-SELF-TEST")
                .signatureMethod("RS256")
                .timestamp(timestamp)
                .nonce(nonce)
                .signature(signature)
                .accessToken(accessToken)
                .build();
        System.out.println("AUTH HEADER:");
        System.out.println(authHeader.toJson());

        return authHeader;
    }

    private static SingpassAuthHeader createPostAuthHeader(String code, String state) throws Exception {
        Random rand = SecureRandom.getInstance("SHA1PRNG");
        long nonce = rand.nextLong();
        long timestamp = System.currentTimeMillis();
        String baseString = generateBaseStringPost(nonce, timestamp, code, state);
        String signature = sign(baseString);

        var authHeader = SingpassAuthHeader.builder()
                .appId("STG2-SGVERIFY-SELF-TEST")
                .signatureMethod("RS256")
                .timestamp(timestamp)
                .nonce(nonce)
                .signature(signature)
                .build();
        return authHeader;
    }

    public static String sign(String baseString) throws Exception {
        PrivateKey privateKey = loadPrivateKey();

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(baseString.getBytes());
        byte[] signedData = sig.sign();
        String signature = Base64.getEncoder().encodeToString(signedData);
        return signature;
    }

    private static PrivateKey loadPrivateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(""), "DemoApp".toCharArray());
        return (PrivateKey) keyStore.getKey("1", "DemoApp".toCharArray());
    }

    private static String generateBaseStringPost(long nonce, long timestamp, String code, String state) {
        return "POST&" + TOKEN_URL +
                "&app_id=STG2-SGVERIFY-SELF-TEST" +
                "&client_id=STG2-SGVERIFY-SELF-TEST" +
                "&client_secret=WnBdUYAftjB8gLt4cjl1N01XulG1q7fn" +
                "&code=" + code +
                "&grant_type=authorization_code" +
                "&nonce=" + nonce +
                "&redirect_uri=http://localhost:3001/callback" +
                "&signature_method=RS256" +
                "&state=" + state +
                "&timestamp=" + timestamp;
    }

    private static String generateBaseStringGet(String url, long nonce, long timestamp, String attributes, UUID txnNo) {
        return "GET&" + url +
                "&app_id=STG2-SGVERIFY-SELF-TEST" +
                "&attributes=" + attributes +
                "&client_id=STG2-SGVERIFY-SELF-TEST" +
                "&nonce=" + nonce +
                "&signature_method=RS256" +
                "&timestamp=" + timestamp +
                "&txnNo=" + txnNo;
    }
}
