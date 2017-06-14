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
import net.minidev.json.JSONArray;

import java.io.InputStream;
import java.text.ParseException;
import java.util.*;

/**
 *
 */
public class JWEMain {

    public static void main(String[] args) {
        Map<String, Info> info = new HashMap<>();
        //   user name, apiKey/roles
        info.put("Rudy", new Info("49c2b80f-12a5-4464-abad-152cc2cacedb", newRoles("user", "manager")));
        info.put("Soteria", new Info("0a1726c7-068a-4de0-ac64-d27a52cbfce2", newRoles("user")));

        System.out.println("Correct tokens");
        info.forEach(
                (k, v) -> {
                    String publicContent = readFile(v.getApiKey() + ".jwk");
                    try {
                        JWK publicJWK = JWK.parse(publicContent);

                        String apiKey = publicJWK.getKeyID();

                        System.out.println("Subject = " + k + " -> token = " + createToken(k, (RSAKey) publicJWK, apiKey, v.getRoles()));
                    } catch (ParseException | JOSEException e) {
                        e.printStackTrace();
                    }

                }
        );
    }

    private static List<String> newRoles(String... roles) {
        return new ArrayList<>(Arrays.asList(roles));
    }

    private static String readFile(String fileName) {
        InputStream keys = JWEMain.class.getClassLoader().getResourceAsStream(fileName);
        return new Scanner(keys).useDelimiter("\\Z").next();
    }

    private static String createToken(String subject, RSAKey publicKey, String apiKey, List<String> roleNames) throws JOSEException {

        // Create HMAC signer
        JWSSigner signer = new MACSigner(apiKey);

        // Prepare JWT with claims set
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
        claimsSetBuilder.subject(subject);
        claimsSetBuilder.audience("Soteria RI");  // Your application

        // To make token different each time. Counters the replay attacks.
        claimsSetBuilder.issueTime(new Date());
        claimsSetBuilder.expirationTime(new Date(new Date().getTime() + 60 * 1000));

        JSONArray roleValues = new JSONArray();
        roleValues.addAll(roleNames);

        Map<String, Object> roles = new HashMap<>();
        roles.put("roles", roleValues);

        claimsSetBuilder.claim("realm_access", roles);

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

    private static class Info {
        private String apiKey;
        private List<String> roles;

        public Info(String apiKey, List<String> roles) {
            this.apiKey = apiKey;
            this.roles = roles;
        }

        public String getApiKey() {
            return apiKey;
        }


        public List<String> getRoles() {
            return roles;
        }
    }
}