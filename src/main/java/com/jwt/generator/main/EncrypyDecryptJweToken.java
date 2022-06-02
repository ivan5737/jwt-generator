package com.jwt.generator.main;

import com.jwt.generator.constants.Constants;
import com.jwt.generator.util.KeyGenerator;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.extern.slf4j.Slf4j;

import java.util.Date;
import java.util.UUID;

@Slf4j
public class EncrypyDecryptJweToken {

  /**
   * Main method to test the JWE token generator.
   * 
   * @param args of the main class
   */
  public static void main(String[] args) {

    try {
      final KeyGenerator keyGenerator = new KeyGenerator().generatePublicKey();

      JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();
      claimsSet.issuer("test-user");
      claimsSet.subject("JWE-Authentication-Example");

      // User specified claims
      claimsSet.claim("appId", "230919131512092005");
      claimsSet.claim("userId", "4431d8dc-2f69-4057-9b83-a59385d18c03");
      claimsSet.claim("role", "Admin");
      claimsSet.claim("applicationType", "WEB");
      claimsSet.claim("clientRemoteAddress", "192.168.1.2");

      claimsSet.expirationTime(new Date(new Date().getTime() + 1000 * 60 * 10));
      claimsSet.notBeforeTime(new Date());
      claimsSet.jwtID(UUID.randomUUID().toString());

      log.info("Claim Set : \n" + claimsSet.build());

      // Create the JWE header and specify:
      // RSA-OAEP as the encryption algorithm
      // 128-bit AES/GCM as the encryption method
      JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);

      // Initialized the EncryptedJWT object
      EncryptedJWT jwt = new EncryptedJWT(header, claimsSet.build());

      // Create an RSA encrypted with the specified public RSA key
      RSAEncrypter encrypter = new RSAEncrypter(keyGenerator.getPublicRsaKey());

      // Doing the actual encryption
      jwt.encrypt(encrypter);

      // Serialize to JWT compact form
      String jwtString = jwt.serialize();
      log.info("");
      log.info("========================= Encrypted JWE token ==================================");
      log.info("");
      log.info("\n JWE token : " + jwtString);
      log.info("");

      // In order to read back the data from the token using your private RSA key:
      // parse the JWT text string using EncryptedJWT object
      jwt = EncryptedJWT.parse(jwtString);

      // Create a decrypter with the specified private RSA key
      RSADecrypter decrypter = new RSADecrypter(keyGenerator.getPrivateRsaKey());

      // Doing the decryption
      jwt.decrypt(decrypter);

      // Print out the claims from decrypted token
      log.info(
          "======================== Decrypted payload values ===================================");
      log.info("");

      log.info("Issuer: [ " + jwt.getJWTClaimsSet().getIssuer() + "]");
      log.info("Subject: [" + jwt.getJWTClaimsSet().getSubject() + "]");
      log.info("Expiration Time: [" + jwt.getJWTClaimsSet().getExpirationTime() + "]");
      log.info("Not Before Time: [" + jwt.getJWTClaimsSet().getNotBeforeTime() + "]");
      log.info("JWT ID: [" + jwt.getJWTClaimsSet().getJWTID() + "]");

      log.info("Application Id: [" + jwt.getJWTClaimsSet().getClaim("appId") + "]");
      log.info("User Id: [" + jwt.getJWTClaimsSet().getClaim("userId") + "]");
      log.info("Role type: [" + jwt.getJWTClaimsSet().getClaim("role") + "]");
      log.info("Application Type: [" + jwt.getJWTClaimsSet().getClaim("applicationType") + "]");
      log.info(
          "Client Remote Address: [" + jwt.getJWTClaimsSet().getClaim("clientRemoteAddress") + "]");



      log.info("");
      log.info("================================================================================");

      log.info("Public key Modulus:   {}", keyGenerator.getPublicRsaKey().getModulus());
      log.info("Public key Exponent:  {}", keyGenerator.getPublicRsaKey().getPublicExponent());
      log.info("Private key Modulus:  {}", keyGenerator.getPrivateRsaKey().getModulus());
      log.info("Private key Exponent: {}", keyGenerator.getPrivateRsaKey().getPrivateExponent());

      log.info("Public key: {}", keyGenerator.getPublicRsaKey());
    } catch (Exception ex) {
      log.error(Constants.ERROR, ex);
    }

  }

}
