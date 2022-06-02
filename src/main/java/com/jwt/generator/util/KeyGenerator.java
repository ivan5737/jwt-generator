package com.jwt.generator.util;

import com.jwt.generator.constants.Constants;
import com.jwt.generator.exception.JwtGeneratorException;
import com.jwt.generator.exception.constants.LocationError;
import com.jwt.generator.model.RsaData;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

@Slf4j
@Data
public class KeyGenerator {

  private RSAPublicKey publicRsaKey;

  private RSAPrivateKey privateRsaKey;

  private String keyId;

  /**
   * Method to generate the Public and Private Key.
   * 
   * @return the RSAPublicKey, RSAPrivateKey and id.
   */
  public KeyGenerator generatePublicKey() {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(Constants.ALGORITHM);
      // Initialize key size
      keyPairGenerator.initialize(2048);
      // Generate the key pair
      KeyPair keyPair = keyPairGenerator.genKeyPair();

      // Create KeyFactory and RSA Keys Specs
      KeyFactory keyFactory = KeyFactory.getInstance(Constants.ALGORITHM);
      RSAPublicKeySpec publicKeySpec =
          keyFactory.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
      RSAPrivateKeySpec privateKeySpec =
          keyFactory.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);

      // Generate (and retrieve) RSA Keys from the KeyFactory using Keys Specs
      publicRsaKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
      privateRsaKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
      keyId = generateKeyId();
      return this;
    } catch (NoSuchAlgorithmException nsaex) {
      log.error(Constants.ERROR, nsaex);
      throw new JwtGeneratorException(nsaex.getMessage(),
          LocationError.GENERATE_PUBLIC_KEY_NSAEX.name());
    } catch (InvalidKeySpecException ikex) {
      log.error(Constants.ERROR, ikex);
      throw new JwtGeneratorException(ikex.getMessage(),
          LocationError.GENERATE_PUBLIC_KEY_IKEX.name());
    }
  }

  private String generateKeyId() throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance(Constants.DIGEST_ALGORITHM);
    md.update(publicRsaKey.getEncoded());
    byte[] fingerprint = md.digest();
    return Base64.getEncoder().encodeToString(fingerprint);
  }

  public RsaData publicKeyData() {
    return RsaData.builder().modulus(getPublicRsaKey().getModulus())
        .exponent(getPublicRsaKey().getPublicExponent()).keyId(getKeyId()).build();
  }

  public RsaData privateKeyData() {
    return RsaData.builder().modulus(getPrivateRsaKey().getModulus())
        .exponent(getPrivateRsaKey().getPrivateExponent()).keyId(getKeyId()).build();
  }

  public void logKeys() {
    log.info("Public Key:  {}", getPublicRsaKey());
    log.info("Private Key: {}", getPrivateRsaKey());
  }

}
