package com.jwt.generator.service;


import com.jwt.generator.constants.Constants;
import com.jwt.generator.exception.JwtGeneratorException;
import com.jwt.generator.exception.constants.LocationError;
import com.jwt.generator.model.JwtData;
import com.jwt.generator.model.JwtDecrypted;
import com.jwt.generator.model.RsaData;
import com.jwt.generator.repository.PrivateKeyRepository;
import com.jwt.generator.util.KeyGenerator;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class ServiceJwt {

  private final PrivateKeyRepository keyRepository;

  /**
   * First method that generate the Public and Private keys, also save the Private key in the DB.
   * 
   * @return the RsaData with the Modulus and Exponent of the Public key and the Id.
   */
  public RsaData generateKeys() {
    try {
      log.info("================Generando llave Privada y Publica================");
      KeyGenerator keyGenerator = new KeyGenerator().generatePublicKey();

      log.info("===============Imprimiendo llave Privada y Publica===============");
      keyGenerator.logKeys();

      log.info("==================Guardando llave Privada en BD==================\n");
      keyRepository.savePrivateKeyInDb(keyGenerator.privateKeyData());
      return keyGenerator.publicKeyData();
    } catch (JwtGeneratorException jgex) {
      log.error(Constants.ERROR, jgex);
      throw jgex;
    } catch (Exception ex) {
      log.error(Constants.ERROR, ex);
      throw new JwtGeneratorException(ex.getMessage(), LocationError.GENERATE_KEY.name());
    }
  }

  /**
   * Second method that generate the JWT from the Public key.
   * 
   * @param rsaData that contains the Modulus, Exponent and ID of the Public key.
   * @return JwtDecrypted
   */
  public JwtDecrypted generateJwt(RsaData rsaData) {
    try {
      log.info("==================Generando Claims===================");
      JWTClaimsSet.Builder claimsSet = generateClaim();

      JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);
      EncryptedJWT jwt = new EncryptedJWT(header, claimsSet.build());

      log.info("=================Generando Public Key================");
      RSAPublicKey publicRsaKey = generateRsaPublicKey(rsaData);
      RSAEncrypter encrypter = new RSAEncrypter(publicRsaKey);

      log.info("===================Encriptando JWT===================\n");
      jwt.encrypt(encrypter);

      return generateJwtResponse(jwt, rsaData.getId());
    } catch (Exception ex) {
      log.error(Constants.ERROR, ex);
      throw new JwtGeneratorException(ex.getMessage(), LocationError.GENERATE_JWT.name());
    }

  }

  private JWTClaimsSet.Builder generateClaim() {
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
    return claimsSet;
  }

  private RSAPublicKey generateRsaPublicKey(RsaData rsaData)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeyFactory keyFactory = KeyFactory.getInstance(Constants.ALGORITHM);
    RSAPublicKeySpec publicKeySpec =
        new RSAPublicKeySpec(rsaData.getModulus(), rsaData.getExponent());
    return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
  }

  private JwtDecrypted generateJwtResponse(EncryptedJWT jwt, String id) {
    String jwtString = jwt.serialize();
    return JwtDecrypted.builder().jwt(jwtString).id(id).build();
  }

  /**
   * Third method that decrypt the JWT with the Private Key saved in the DB,
   * 
   * @param jwtDecrypted variable that contains the JWT decrypted with the ID.
   * @return JwtData decrypted.
   */
  public JwtData decryptJwt(JwtDecrypted jwtDecrypted) {
    try {
      log.info("==================Buscando llave Privada en BD==================");
      RsaData privateKey = keyRepository.getPrivateKey(jwtDecrypted.getId());

      log.info("===================Generando RSA Private Key====================");
      RSAPrivateKey privateRsaKey = generatePrivateKey(privateKey);
      RSADecrypter decrypter = new RSADecrypter(privateRsaKey);

      log.info("=======================Generando JWT Enc========================\n");
      EncryptedJWT jwt = EncryptedJWT.parse(jwtDecrypted.getJwt());
      jwt.decrypt(decrypter);

      return bindingJwtData(jwt);
    } catch (EmptyResultDataAccessException daex) {
      log.error(Constants.ERROR, daex);
      throw new JwtGeneratorException(Constants.ERROR_ID_SEARCH,
          LocationError.DECRYPTED_JWT_SEARCHING_ID.name());
    } catch (Exception ex) {
      log.error(Constants.ERROR, ex);
      throw new JwtGeneratorException(ex.getMessage(), LocationError.DECRYPTED_JWT.name());
    }
  }

  private JwtData bindingJwtData(EncryptedJWT jwt) throws ParseException {
    return JwtData.builder().issuer(jwt.getJWTClaimsSet().getIssuer())
        .subject(jwt.getJWTClaimsSet().getSubject())
        .expirationTime(jwt.getJWTClaimsSet().getExpirationTime())
        .notBeforeTime(jwt.getJWTClaimsSet().getNotBeforeTime())
        .jwtId(jwt.getJWTClaimsSet().getJWTID())
        .appId((String) jwt.getJWTClaimsSet().getClaim("appId"))
        .userId((String) jwt.getJWTClaimsSet().getClaim("userId"))
        .role((String) jwt.getJWTClaimsSet().getClaim("role"))
        .applicationType((String) jwt.getJWTClaimsSet().getClaim("applicationType"))
        .clientRemoteAddress((String) jwt.getJWTClaimsSet().getClaim("clientRemoteAddress"))
        .build();
  }

  private RSAPrivateKey generatePrivateKey(RsaData rsaData)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeyFactory keyFactory = KeyFactory.getInstance(Constants.ALGORITHM);
    RSAPrivateKeySpec privateKeySpec =
        new RSAPrivateKeySpec(rsaData.getModulus(), rsaData.getExponent());
    return (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
  }

}
