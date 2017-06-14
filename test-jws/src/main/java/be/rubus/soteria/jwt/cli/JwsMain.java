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
package be.rubus.soteria.jwt.cli;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;

import java.text.ParseException;
import java.util.*;

/**
 *
 */
public class JwsMain {

    public static void main(String[] args) throws JOSEException, ParseException {
        List<Info> data = new ArrayList<>();

        data.add(new Info("Key Soteria", "Soteria RI", "ILoveJavaEESecurityWithSoteriaRI".getBytes(), newRoles("user", "manager")));
        data.add(new Info("Key Alphabet", "Alphabet", "Thelynxdrankfivemojitosatthepub!".getBytes(), newRoles("user")));

        System.out.println("Correct tokens");
        data.forEach(
                i -> System.out.println("Subject = " + i.getUserName() + " -> token = " + createToken(i))
        );

        System.out.println("Incorrect tokens");
        Info info = new Info(data.get(0).apiKey, data.get(1).getUserName(), data.get(0).getHashKey(), Collections.emptyList());
        System.out.println("(Signed with wrong key for subject) Subject = " + info.getUserName() + " -> token = " + createToken(info));

        info = new Info(data.get(1).apiKey, data.get(1).getUserName(), data.get(0).getHashKey(), Collections.emptyList());
        System.out.println("(key does not match api key) Subject = " + info.getUserName() + " -> token = " + createToken(info));
    }

    private static List<String> newRoles(String... roles) {
        return new ArrayList<>(Arrays.asList(roles));
    }

    private static String createToken(Info info) {
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
        claimsSetBuilder.subject(info.getUserName());

        claimsSetBuilder.issueTime(new Date());
        claimsSetBuilder.expirationTime(new Date(new Date().getTime() + 60 * 1000));

        JSONArray roleValues = new JSONArray();
        roleValues.addAll(info.getRoles());

        Map<String, Object> roles = new HashMap<>();
        roles.put("roles", roleValues);

        claimsSetBuilder.claim("realm_access", roles);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).keyID(info.getApiKey()).build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSetBuilder.build());

        try {
            JWSSigner signer = new MACSigner(info.getHashKey());

            signedJWT.sign(signer);
        } catch (JOSEException e) {
            // Should not happen
            e.printStackTrace();
        }

        return signedJWT.serialize();
    }

    private static class Info {
        private String apiKey;
        private String userName;
        private byte[] hashKey;
        private List<String> roles;

        public Info(String apiKey, String userName, byte[] hashKey, List<String> roles) {
            this.apiKey = apiKey;
            this.userName = userName;
            this.hashKey = hashKey;
            this.roles = roles;
        }

        public String getApiKey() {
            return apiKey;
        }

        public String getUserName() {
            return userName;
        }

        public byte[] getHashKey() {
            return hashKey;
        }

        public List<String> getRoles() {
            return roles;
        }
    }
}
