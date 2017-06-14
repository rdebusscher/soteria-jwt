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

import be.rubus.soteria.jwt.JWTCredential;

import javax.annotation.PostConstruct;
import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class JwtIdentityStore implements IdentityStore {

    private Map<String, String> users;
    //          UserName,  api-key

    @PostConstruct
    public void init() {
        users = new HashMap<>();
        users.put("Soteria RI", "Key Soteria");
        users.put("Alphabet", "Key Alphabet");

    }

    @Override
    public CredentialValidationResult validate(Credential credential) {
        CredentialValidationResult result;
        if (credential instanceof JWTCredential) {

            // This means we had a valid JWT, so user is valid.
            JWTCredential jwtCredential = (JWTCredential) credential;
            String caller = jwtCredential.getCaller();

            // Does the userName match the apiKey
            Serializable xApiKey = jwtCredential.getInfo(DemoJWTHandler.API_KEY);
            if (xApiKey == null || !xApiKey.equals(users.get(caller))) {

                result = CredentialValidationResult.INVALID_RESULT;
            } else {

                result = new CredentialValidationResult(caller, jwtCredential.getRoles());
            }
        } else {
            result = CredentialValidationResult.INVALID_RESULT;
        }
        return result;
    }
}
