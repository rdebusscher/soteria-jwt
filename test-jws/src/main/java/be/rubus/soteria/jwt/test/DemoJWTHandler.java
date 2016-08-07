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
package be.rubus.soteria.jwt.test;

import be.rubus.soteria.jwt.JWTTokenHandler;
import be.rubus.soteria.jwt.JWTUsernameCredential;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;

import javax.annotation.PostConstruct;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class DemoJWTHandler implements JWTTokenHandler {

    public static final String API_KEY = "xApiKey";

    private Map<String, byte[]> keys;
    //          key , hash key

    @PostConstruct
    public void init() {
        keys = new HashMap<>();
        keys.put("Key Soteria", "ILoveJavaEESecurityWithSoteriaRI".getBytes());
        keys.put("Key Alphabet", "Thelynxdrankfivemojitosatthepub!".getBytes());
    }

    @Override
    public JWTUsernameCredential retrieveCredential(String token) {
        JWTUsernameCredential result = null;
        try {
            JWSObject jws = JWSObject.parse(token);

            String apiKey = jws.getHeader().getKeyID();
            if (apiKey != null && keys.containsKey(apiKey)) {

                byte[] sharedSecret = keys.get(apiKey);
                JWSVerifier verifier = new MACVerifier(sharedSecret);

                if (jws.verify(verifier)) {
                    JWTClaimsSet claimsSet = JWTClaimsSet.parse(jws.getPayload().toJSONObject());

                    // Verify time validity of token.
                    Date creationTime = claimsSet.getIssueTime();
                    Date expirationTime = claimsSet.getExpirationTime();
                    Date now = new Date();
                    long validityPeriod = expirationTime.getTime() - creationTime.getTime();
                    if (creationTime.before(now) && now.before(expirationTime) && validityPeriod < 120000 /*2 minutes*/) {

                        result = new JWTUsernameCredential(claimsSet.getSubject());
                        result.addInfo(API_KEY, apiKey);
                    }
                }
            }
        } catch (ParseException | JOSEException e) {
            ; // Token is nog valid
        }
        return result;
    }
}
