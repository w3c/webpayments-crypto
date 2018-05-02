# Objective

* Provide a standard way for encryption of sensitive information
* Provide Data Integrity for encrypted payload
* Use existing standards for algorithms and message structure

# Asymmetric Encryption

## **Parties involved in encryption**

### Data Receiver (Bob)

Bob is intending to receive sensitive information. Bob shares his public key with Alice.

### Data Provider (Alice)

Alice uses public key provided by Bob to encrypt sensitive data.

### Attacker (Eve)

Eve tries to get information about communication between Bob and Alice and misuse the information for her benefit.

## **Public Key Definition**

**Algorithm**: RSA
**Key Length**: 2048 bits

The public key shared by Bob would be in [certificate format (X.509)](https://en.wikipedia.org/wiki/X.509). The file should be in [PEM format](https://tools.ietf.org/html/rfc7468) (E.g. '*.pem')

## **Encryption of Data & Data Integrity**

A random AES 256 bit key would be generated and used as CEK (Content Encryption Key). CEK would be used to encrypt payload with algorithm of AES-256-GCM. This would generate IV and Authentication Tag. Authentication Tag is like MAC(Message Authentication Code) and provides data integrity. After encryption of data CEK would be encrypted using RSA_OAEP_256 algorithm.

* Data Encryption:
  * Algorithm : AES-256-GCM
  * Key length : 256 bits

* Key Encryption:
  * Algorithm : RSA_OAEP_256
  * Key Length : 2048 bits



## **Message Structure**

JWT already is well recognized in the industry for encryption of JSON.
In general it has message structure as

**(header).(encrypted key).(iv).(cipher text).(integrity value)**

### Header
Following headers would be generated as outcome of encryption.

{ "enc":"A256GCM",
  "alg":"RSA-OAEP-256"
}
This would be base64 encoded.

### Encrypted Key

Encrypted Key will be random generated CEK encrypted with RSA public key.

* Key Encryption:
  * Algorithm : RSA_OAEP_256
  * Key Length : 2048 bits

### Initialization Vector

The initialization vector that is used in encryption will be shared for decryption of cipher text.

### Cipher text

This is payload encrypted by use of AES 256 bits key and AES-GCM algorithm.

### Integrity value

This would be generated as part of AES-GCM algorithm. Also known as Authentication tag. This allows Bob to know if anyone has altered the message.

## Message Sample:

eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.CucrNRoLT0kkBS0MxlGq9_HsPwX_ggJ8p-kB72tA_3Rt-WkH3YQt6KOYci7YuPkFjRLFPj__i1EmXXwpqTF1FUF9posbsamSGGIRQiFRfS0qopTTGEk_aWK0ngxe5T3O8Y8m7MsZnwTdlO945u13Q2brWnsHa2yY_NyRdXXNo2FmkSurvR7DGR8A00UYlCweQOius0u2YQ8Gy93OrvZAQm7qBwFG8Lf9rDadCUdZPeDIM1iUKBwaylOYS_xkISVKJhdnw59RQGl-iumKx4DX3h0PY2LREK8cI7ZoRbhpCWZkQHe2U6stIljteZ94URMVWzda5wkYL8yCqalbvtYbJA.QSfbdD74z2tn7xXr.9zNqMmvYDh9fVwjVGPzQGM9KveFxZP-HXlf8u4Vo3lasp-gjMNDZmz9enfgTemz6xQvOi05Q2fvAP2AurtORPei3st3tPZZBYUbl4d4WWuRLsEJsqzRyT7WRfqSramV8IhDUXG0TKxg1hg_008g-bOnbjjvFWqiDkoHeAnA5mid6R-JysFbkgJJohngQN53pNNrV0eQYBaCS7dkvdcKn97vUE806OYPRpzwDKw.nrAvFnyvf4PgQfPJ8RDmYA

## Sample Code using Nimbus (Connect2id)

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

Encryption using AES-256-GCM and RSA_OAEP_256

```java
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

Decryption using RSA private key.

```java
// Parse back
jwt = EncryptedJWT.parse(jwtString);

// Create a decrypter with the specified private RSA key
RSADecrypter decrypter = new RSADecrypter(privateKey);
jwt.decrypt(decrypter);
String decryptedJson = jwt.serialize();

```






# References

* X.509 certificate format: https://en.wikipedia.org/wiki/X.509
* JWT RFC - https://tools.ietf.org/html/rfc7519
* AES GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
* Nimbus (Connect2id) Example : https://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-rsa-encryption
