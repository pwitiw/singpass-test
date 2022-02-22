package com.example.demo;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.*;
import okhttp3.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.time.Instant;
import java.util.Base64;
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
                redirect_uri,
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
    private final String timestamp;
    private final String nonce;
    private final String appId;
    private final String signatureMethod;
    private final String signature;

    String toJson() {
        return "PKI_SIGN " +
                "app_id=\"" + appId +
                "\",nonce=\"" + nonce +
                "\",signature_method=\"" + signatureMethod +
                "\",signature=\"" + signature +
                "\",timestamp=\"" + timestamp +
                "\"";
    }
}

@RequiredArgsConstructor
@Getter
@Builder
@ToString
class RequestDetails {
    private final String method;
    private final String url;
    private final String appId;
    private final String attributes;
    private final String clientId;
    private final String clientSecret;
    private final String code;
    private final String grantType;
    private final String nonce;
    private final String redirectUri;
    private final String state;
    private final String timestamp;

//    String compose() {
//        var result = new StringBuilder()
//                .append(method)
//                .append(url)
//                .append("app_id=").append(appId);
//        if (attributes != null) {
//            result.append("attributes=").append(attributes);
//        }
//        result.
//        return "PKI_SIGN timestamp=\"" + timestamp +
//                "\",nonce=\"" + nonce +
//                "\",app_id=\"" + appId +
//                "\",signature_method=\"" + signatureMethod +
//                "\",signature=\"" + signature +
//                "\"";
//    }
}
//        return method + "&" + url + "&app_id=STG2-SGVERIFY-SELF-TEST&client_id=STG2-SGVERIFY-SELF-TEST&client_secret=WnBdUYAftjB8gLt4cjl1N01XulG1q7fn&code=0b43b47773205a7779d5a572fd3ae841820a8eaa&grant_typ" +
//                "e=authorization_code&nonce=" + nonce + "&redirect_uri=http://localhost:3001/callback&signature_method=RS256&state=" + state + "&timestamp=" + timestamp;
//        return "GET&https://test.api.myinfo.gov.sg/sgverify/v2/person/" + uuid + "&app_id=STG2-SGVERIFY-SELF-TEST&attributes=" + attributes + "&client_id=STG2-SGVERIFY-SELF-TEST" +
//                "&nonce=" + nonce + "&redirect_uri=http://localhost:3001/callback&signature_method=RS256&state=" + state + "&timestamp=" + timestamp;


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

        var authorizationHeaderApiCall = createPostAuthHeader(state, code).toJson();

        OkHttpClient client = new OkHttpClient.Builder()
                .build();
        var requestBody = okhttp3.RequestBody.create(singpassTokenRequestBody.postowe(), MediaType.parse("application/json"));
        System.out.println("REQUEST BODY: " + singpassTokenRequestBody.postowe());
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

        var strParams = "client_id=" + singpassTokenRequestBody.getClient_id() +
                "&attributes=partialuinfin,name,race,dob,mobileno,uuid" +
                "&txnNo=" + "testTxn" + UUID.randomUUID().toString();
        var chunks = singpassResponse.getAccessToken().split("\\.");
        var payload = new String(Base64.getDecoder().decode(chunks[1]));
        var json = new JSONObject(payload);
        String attributes = attributes(json.getJSONArray("scope"));
        var url = PERSON_URL + "/" + json.get("sub");
        var fullPath = url + "?" + strParams;
        Request requestUserDetails = new Request.Builder()
                .url(fullPath)
                .get()
                .header("Cache-Control", "no-cache")
                .header("Authorization", createGetAuthHeader(url, state, attributes).toJson() + ",Bearer " + singpassResponse.getAccessToken())
                .build();
        Response userDataResponse = client.newCall(requestUserDetails).execute();
        var userData = userDataResponse.body().string();
        return userData;
    }

    private String attributes(JSONArray scope) {
        return StreamSupport.stream(scope.spliterator(), false)
                .map(String::valueOf)
                .reduce((a, b) -> a + "s" + b)
                .orElse("");
    }

    private static SingpassAuthHeader createGetAuthHeader(String url, String state, String attributes) throws Exception {
        String nonce = UUID.randomUUID().toString();
        String timestamp = String.valueOf(Instant.now().toEpochMilli());
        PrivateKey privateKey = loadPrivateKey();

        byte[] data = generateBaseStringGet(url, nonce, timestamp, state, attributes).getBytes("UTF8");

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(data);
        byte[] digitalSignature = sig.sign();
        Files.writeString(Paths.get("digital_signature_2"), new String(digitalSignature));
        String signature = new String(Base64.getEncoder().encode(digitalSignature));
//        sig.initVerify(privateKey.getPublic());
//        sig.update(data);

        var authHeader = SingpassAuthHeader.builder()
                .appId("STG2-SGVERIFY-SELF-TEST")
                .signatureMethod("RS256")
                .timestamp(timestamp)
                .nonce(nonce)
                .signature(signature)
                .build();

        System.out.println(sig.verify(digitalSignature));
        System.out.println(authHeader);

        return authHeader;
    }

    private static SingpassAuthHeader createPostAuthHeader(String state, String code) throws Exception {
        String nonce = UUID.randomUUID().toString();
        String timestamp = String.valueOf(Instant.now().toEpochMilli());
        String baseString = generateBaseStringPost(nonce, timestamp, state, code);
        String signature = sign(baseString);
        System.out.println("BASE STRING: " + baseString);
        System.out.println("SIGNATURE: " + signature);

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

        byte[] data = baseString.getBytes("UTF8");

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(data);
        byte[] digitalSignature = sig.sign();
        Files.writeString(Paths.get("digital_signature_2"), new String(digitalSignature));
        String signature = new String(Base64.getEncoder().encode(digitalSignature));
//        sig.initVerify(privateKey);
//        sig.update(data);
        return signature;
    }

    private static PrivateKey loadPrivateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        // TODO zmienic path
        keyStore.load(new FileInputStream(""), "DemoApp".toCharArray());
        return (PrivateKey) keyStore.getKey("1", "DemoApp".toCharArray());
    }

    private static String generateBaseStringPost(String nonce, String timestamp, String state, String code) {
        return "POST&" + TOKEN_URL + "&app_id=STG2-SGVERIFY-SELF-TEST&client_id=STG2-SGVERIFY-SELF-TEST&client_secret=WnBdUYAftjB8gLt4cjl1N01XulG1q7fn&code="+code+"&grant_typ" +
                "e=authorization_code&nonce=" + nonce + "&redirect_uri=http://localhost:3001/callback&signature_method=RS256&state=" + state + "&timestamp=" + timestamp;
    }

    private static String generateBaseStringGet(String url, String nonce, String timestamp, String state, String attributes) {
        return "GET&" + url + "&app_id=STG2-SGVERIFY-SELF-TEST&attributes=" + attributes + "&client_id=STG2-SGVERIFY-SELF-TEST" +
                "&nonce=" + nonce + "&redirect_uri=http://localhost:3001/callback&signature_method=RS256&state=" + state + "&timestamp=" + timestamp;
    }
}
