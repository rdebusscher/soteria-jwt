# soteria-jwt
POC for JWT integration with Soteria RI

## Goal

Example of using authentication with JWT in a machine to machine communication using JAX-RS.
 
This is the general idea
- The other party gets a user name, an api key and a key (hash key or public part of RSA key)
- They generate a JWS or JWE with the api key in the header, the user name as subject claim and signed (or encrypted) with the key.
- The server determines based on the api key the key which will be used to verify the signing or use for decryption. The subject - api key combination can be verified to be valid.

We should be able to determine which other party calls us, not only that the other side can present us a valid token.

This repository contains all the code to integrate with Soteria, JWT framework (Nimbus - JOSE) and example code.

## License

[http://www.apache.org/licenses/LICENSE-2.0](Apache License, Version 2.0)

## Compatibility

The code should work on all Java EE 7 servers which support Soteria (Payara 4.1.1.161, JBoss WildFly 10 and TomEE 7.0.0-SNAPSHOT (from 05-05-2016 or later) ) but is only tested on WildFly for the moment. 

## JWS

The JWS example uses a hash key to sign the payload and generate a JWS. This JWS token can be presented to a JAX-RS endpoint protected by Soteria. It returns the user name of the token if it is valid.

These are the steps to run the example.
- Run the main() of *be.rubus.soteria.jwt.cli.JwsMain*
It generates some valid and invalid tokens. The correct tokens are also only 1 minute valid and expires then.
- Present the token in the header
Authorization: Bearer <token>
- Of the URL http://localhost:8080/soteria-jws/data/hello

You should receive the message 'hello xxx' or an unauthorized response.

## JWE

The JWE example uses a RSA key to encrypt the payload and generate a JWE. This JWE token can be presented to a JAX-RS endpoint protected by Soteria. It returns the user name of the token if it is valid.

This encryption version has no benefit over using a plain JWS (as in the above example) since the payload does not contain any secret data (onlues you want to shield of the user name also which is accomplished in this example)

These are the steps to run the example.
- Run the main() of be.rubus.soteria.jwe.cli.JWEMain
It generates 2 valid tokens which can be used.
- Present the token in the header
Authorization: Bearer <token>
- Of the URL http://localhost:8080/soteria-jwe/data/hello

You should receive the message 'hello xxx' or an unauthorized response.

With the program JWKManager you can create additional RSA keys.

With the program *be.rubus.soteria.jwe.cli.JWKManager* you can generate additional RSA keys which can be used by the demo programs. 