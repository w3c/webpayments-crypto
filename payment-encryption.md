# Asymmetric Encryption
## Unofficial Draft 07 May 2018

### Latest editor's draft:  https://w3c.github.io/TBD
### Editors:
   Ian Jacobs
   
### Participate:
  [https://github.com/w3c/webpayments-crypto/blob/master/payment-encryption.md GitHub w3c/webpayments-crypto]

  [https://github.com/w3c/webpayments-crypto/issues File a bug]

  [https://github.com/w3c/webpayments-methods-tokenization/commits/gh-pages Commit history]

  [https://github.com/w3c/webpayments-methods-tokenization/pulls/ Pull requests]

This document is licensed under a [https://creativecommons.org/licenses/by/3.0/ Creative Commons Attribution 3.0 License].
   

## Abstract
This specification provides a standard way for encryption of sensitive information to provide data integrity for encrypted payload using existing standards for algorithms and message structure.

## Status of This Document
This document is draft of a potential specification. It has no official standing of any kind and does not represent the support or consensus of any standards organisation.
The working group maintains [https://github.com/w3c/webpayments-crypto/issues a list of all bug reports that the group has not yet addressed]. Pull requests with proposed specification text for outstanding issues are strongly encouraged.

## 1. Introduction
''This section is non-normative.''

Information security has grown to be a colossal factor, especially with modern communication networks, leaving loopholes that could be leveraged to devastating effects. To tighten communication security, Asymmetric encryption is commonly used. Encryption is the process of locking up information using cryptography. Asymmetric cryptography, also known as public key cryptography, uses public and private keys to encrypt and decrypt data. The keys are simply large numbers that have been paired together but are not identical (asymmetric). One key in the pair can be shared with everyone; it is called the public key. The other key in the pair is kept secret; it is called the private key. Either of the keys can be used to encrypt a message; the opposite key from the one used to encrypt the message is used for decryption.
This document describes how asymmetric encryption can be used to achieve the security goals.

## 2. Examples of usage
The following parties are involved in encryption:
* Data Receiver (Bob): Bob is intending to receive sensitive information. Bob shares his public key with Alice.
* Data Provider (Alice): Alice uses public key provided by Bob to encrypt sensitive data.
* Attacker (Eve): Eve tries to get information about communication between Bob and Alice and misuse the information for her benefit.
In order for Bob to receive sensitive data from Alice using asymmetric encryption, he first needs to generate a public key and private key pair. The public key can be known to everyone. Bob shares his public key with Alice and keeps his private key secret. Alice then can use Bob’s public key to encrypt sensitive data. Bob can use the private key to decrypt the encrypted data. Attackers such as Eve can’t decrypt the encrypted data as long as Bob keeps his private key secret.

### 2.1 Key generation Example
This sample shows how how to generate a new key pair using a given security provider.
``` java
// Key generation
KeyPairGenerator keyGenerator = null;
try {
    keyGenerator = KeyPairGenerator.getInstance("RSA");
} catch (NoSuchAlgorithmException e) {
    e.printStackTrace();
}
keyGenerator.initialize(2048);

KeyPair kp = keyGenerator.genKeyPair();
RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();
```

### 2.2 Encryption Example
This sample shows how to encrypt a JSON Web Token (JWT) claim set using a specified public key.
``` java
JWTClaimsSet claimsSet = new JWTClaimsSet();
claimsSet.setCustomClaim("cardNumber", "5413339000001513");
claimsSet.setCustomClaim("expiryMonth", "12");
claimsSet.setCustomClaim("expiryYear", "20");
claimsSet.setCustomClaim("cryptogram", "AlhlvxmN2ZKuAAESNFZ4GoABFA==");
claimsSet.setCustomClaim("typeOfCryptogram", "UCAF");
claimsSet.setCustomClaim("trid", "9812345678");
claimsSet.setCustomClaim("eci", "242");


System.out.println(claimsSet.toJSONObject());


// Request JWT encrypted with RSA-OAEP-256 and 128-bit AES/GCM
JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);

// Create the encrypted JWT object
EncryptedJWT jwt = new EncryptedJWT(header, claimsSet);

// Create an encrypter with the specified public RSA key
RSAEncrypter encrypter = new RSAEncrypter(publicKey);

// Do the actual encryption
try {
    jwt.encrypt(encrypter);
} catch (JOSEException e) {
    e.printStackTrace();
}
// Serialise to JWT compact form
String jwtString = jwt.serialize();

System.out.println(jwtString);
```
### 2.3 Decryption Example
This sample shows how to decrypt an encrypted JSON Web Token (JWT) claim set using a specified public key.
``` java
// Parse back
jwt = EncryptedJWT.parse(jwtString);

// Create a decrypter with the specified private RSA key
RSADecrypter decrypter = new RSADecrypter(privateKey);
jwt.decrypt(decrypter);
String decryptedJson = jwt.serialize();
```
## 3. Assumptions
* This specification is designed to address these primary use case
** The sensitive data is in JSON format

## 4. Public Key Definition
Algorithm: RSA Key Length: 2048 bits
The public key shared by data receiver would be in [https://en.wikipedia.org/wiki/X.509 certificate format (X.509)]. The file should be in [https://tools.ietf.org/html/rfc7468 PEM format] (E.g. '*.pem')

## 5. Message Structure
JWT already is well recognized in the industry for encryption of JSON. In general it has message structure as
**(header).(encrypted key).(iv).(cipher text).(integrity value)**

### 5.1 Header
Following headers would be generated as outcome of encryption.

{ "enc":"A256GCM",
  "alg":"RSA-OAEP-256"
}
This would be base64 encoded.

### 5.2 Encrypted Key
Encrypted Key will be random generated CEK encrypted with RSA public key.

* Key Encryption:
  * Algorithm : RSA_OAEP_256
  * Key Length : 2048 bits

### 5.3 Initialization Vector
The initialization vector that is used in encryption will be shared for decryption of cipher text.

### 5.4 Cipher Text
This is payload encrypted by use of AES 256 bits key and AES-GCM algorithm.

### 5.5 Integrity Value
This would be generated as part of AES-GCM algorithm. Also known as Authentication tag. This allows Bob to know if anyone has altered the message.

### 5.6 Message Example

eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.CucrNRoLT0kkBS0MxlGq9_HsPwX_ggJ8p-kB72tA_3Rt-WkH3YQt6KOYci7YuPkFjRLFPj__i1EmXXwpqTF1FUF9posbsamSGGIRQiFRfS0qopTTGEk_aWK0ngxe5T3O8Y8m7MsZnwTdlO945u13Q2brWnsHa2yY_NyRdXXNo2FmkSurvR7DGR8A00UYlCweQOius0u2YQ8Gy93OrvZAQm7qBwFG8Lf9rDadCUdZPeDIM1iUKBwaylOYS_xkISVKJhdnw59RQGl-iumKx4DX3h0PY2LREK8cI7ZoRbhpCWZkQHe2U6stIljteZ94URMVWzda5wkYL8yCqalbvtYbJA.QSfbdD74z2tn7xXr.9zNqMmvYDh9fVwjVGPzQGM9KveFxZP-HXlf8u4Vo3lasp-gjMNDZmz9enfgTemz6xQvOi05Q2fvAP2AurtORPei3st3tPZZBYUbl4d4WWuRLsEJsqzRyT7WRfqSramV8IhDUXG0TKxg1hg_008g-bOnbjjvFWqiDkoHeAnA5mid6R-JysFbkgJJohngQN53pNNrV0eQYBaCS7dkvdcKn97vUE806OYPRpzwDKw.nrAvFnyvf4PgQfPJ8RDmYA



## A. References

* X.509 certificate format: https://en.wikipedia.org/wiki/X.509
* JWT RFC - https://tools.ietf.org/html/rfc7519
* AES GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
* Nimbus (Connect2id) Example : https://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-rsa-encryption
* JWE RFC - https://tools.ietf.org/html/rfc7516
