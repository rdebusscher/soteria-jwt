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

import be.rubus.soteria.jwt.JWTUsernameCredential;

import javax.annotation.PostConstruct;
import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 *
 */
public class JwtIdentityStore implements IdentityStore {

    private Map<String, String> users;
    //          UserName,  api-key

    @PostConstruct
    public void init() {
        // TODO In production situations this should not be hardcoded of course.
        users = new HashMap<>();
        users.put("Rudy", "49c2b80f-12a5-4464-abad-152cc2cacedb");
        users.put("Soteria", "0a1726c7-068a-4de0-ac64-d27a52cbfce2");
    }

    @Override
    public CredentialValidationResult validate(Credential credential) {
        CredentialValidationResult result;
        if (credential instanceof JWTUsernameCredential) {
            // This means we had a valid JWT/JWE.
            String caller = ((JWTUsernameCredential) credential).getCaller();

            // Does the userName match the apiKey
            JWTUsernameCredential jwtCredential = (JWTUsernameCredential) credential;
            Serializable xApiKey = jwtCredential.getInfo(DemoJWTHandler.API_KEY);
            if (xApiKey == null || !xApiKey.equals(users.get(caller))) {

                result = CredentialValidationResult.INVALID_RESULT;
            } else {

                Set<String> groupAssignment = new HashSet<>(); // Here just machine to machine authentication;
                result = new CredentialValidationResult(caller, groupAssignment);
            }
        } else {
            result = CredentialValidationResult.INVALID_RESULT;
        }
        return result;
    }
}
