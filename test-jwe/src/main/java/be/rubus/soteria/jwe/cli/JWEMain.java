/*
 * Copyright 2016 Rudy De Busscher
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package be.rubus.soteria.jwe.cli;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.InputStream;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

/**
 *
 */
public class JWEMain {

    public static void main(String[] args) {
        Map<String, String> info = new HashMap<>();
        //   user name, apiKey
        info.put("Rudy", "49c2b80f-12a5-4464-abad-152cc2cacedb");
        info.put("Soteria", "0a1726c7-068a-4de0-ac64-d27a52cbfce2");

        System.out.println("Correct tokens");
        info.forEach(
                (k, v) -> {
                    String publicContent = readFile(v + ".jwk");
                    try {
                        JWK publicJWK = JWK.parse(publicContent);

                        String apiKey = publicJWK.getKeyID();

                        System.out.println("Subject = " + k + " -> token = " + createToken(k, (RSAKey) publicJWK, apiKey));
                    } catch (ParseException | JOSEException e) {
                        e.printStackTrace();
                    }

                }
        );
    }

    private static String readFile(String fileName) {
        InputStream keys = JWEMain.class.getClassLoader().getResourceAsStream(fileName);
        return new Scanner(keys).useDelimiter("\\Z").next();
    }

    private static String createToken(String subject, RSAKey publicKey, String apiKey) throws JOSEException {

        // Create HMAC signer
        JWSSigner signer = new MACSigner(apiKey);

        // Prepare JWT with claims set
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
        claimsSetBuilder.subject(subject);
        claimsSetBuilder.audience("Soteria RI");  // Your application

        // To make token different each time. Counters the replay attacks.
        claimsSetBuilder.issueTime(new Date());
        claimsSetBuilder.expirationTime(new Date(new Date().getTime() + 60 * 1000));

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSetBuilder.build());

        // Apply the HMAC
        signedJWT.sign(signer);

        // Create JWE object with signed JWT as payload
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                        .contentType("JWT") // required to signal nested JWT
                        .keyID(apiKey)
                        .build(),
                new Payload(signedJWT));

        JWEEncrypter encrypter = new RSAEncrypter(publicKey);

        jweObject.encrypt(encrypter);

        return jweObject.serialize();

    }
}
