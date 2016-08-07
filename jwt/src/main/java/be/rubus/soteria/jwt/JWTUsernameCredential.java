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
package be.rubus.soteria.jwt;

import javax.security.identitystore.credential.Credential;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class JWTUsernameCredential implements Credential {

    private String caller;

    private Map<String, Serializable> info;

    public JWTUsernameCredential(String caller) {
        this.caller = caller;
        info = new HashMap<>();
    }

    @Override
    public String getCaller() {
        return caller;
    }

    public void addInfo(String key, Serializable value) {
        info.put(key, value);
    }

    // TODO Consider Generic Type like
    //public <T> T getInfo(String key)
    public Serializable getInfo(String key) {
        return info.get(key);
    }
}
