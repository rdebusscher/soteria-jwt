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
package be.rubus.soteria.jwe.test;

import be.rubus.soteria.jwe.cli.JWEMain;
import be.rubus.soteria.jwt.JWTTokenHandler;
import be.rubus.soteria.jwt.JWTUsernameCredential;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import javax.annotation.PostConstruct;
import java.io.InputStream;
import java.text.ParseException;
import java.util.Date;
import java.util.Scanner;

/**
 *
 */
public class DemoJWTHandler implements JWTTokenHandler {

    public static final String API_KEY = "xApiKey";

    private JWKSet jwkSet;

    @PostConstruct
    public void init() {
        String privateContent = readFile("private.jwkset");
        try {
            jwkSet = JWKSet.parse(privateContent);
        } catch (ParseException e) {
            e.printStackTrace();
        }
    }

    @Override
    public JWTUsernameCredential retrieveCredential(String token) {
        JWTUsernameCredential result = null;
        try {
            // Parse the JWE string
            JWEObject jweObject = JWEObject.parse(token);
            String apiKey = jweObject.getHeader().getKeyID();
            // Use this apiKey to select the correct privateKey

            RSAKey privateKey = (RSAKey) jwkSet.getKeyByKeyId(apiKey);

            // Decrypt with shared key
            jweObject.decrypt(new RSADecrypter(privateKey));

            // Extract payload
            SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

            // Check the HMAC, Optional
            signedJWT.verify(new MACVerifier(apiKey));

            // Retrieve the JWT claims...
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            // Verify time validity of token.
            Date creationTime = claimsSet.getIssueTime();
            Date expirationTime = claimsSet.getExpirationTime();
            Date now = new Date();

            long validityPeriod = expirationTime.getTime() - creationTime.getTime();
            if (creationTime.before(now) && now.before(expirationTime) && validityPeriod < 120000 /*2 minutes*/) {

                result = new JWTUsernameCredential(claimsSet.getSubject());
                result.addInfo(API_KEY, apiKey);
            }

        } catch (ParseException | JOSEException e) {
            ; // Token is not valid
        }
        return result;
    }

    private static String readFile(String fileName) {
        InputStream keys = JWEMain.class.getClassLoader().getResourceAsStream(fileName);
        return new Scanner(keys).useDelimiter("\\Z").next();
    }

}
