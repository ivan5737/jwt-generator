package com.jwt.generator.util;

import com.jwt.generator.constants.Constants;
import com.jwt.generator.model.RSAdata;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class KeyGenerator {

  private RSAPublicKey publicRsaKey;

  private RSAPrivateKey privateRsaKey;

  private String id;

  public KeyGenerator generatePublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
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
    id = UUID.randomUUID().toString();
    return this;
  }

  public RSAdata publicKeyData() {
    return RSAdata.builder().modulus(getPublicRsaKey().getModulus())
        .exponent(getPublicRsaKey().getPublicExponent()).id(id).build();
  }

  public RSAdata privateKeyData() {
    return RSAdata.builder().modulus(getPrivateRsaKey().getModulus())
        .exponent(getPrivateRsaKey().getPrivateExponent()).id(id).build();
  }

  public void logKeys() {
    log.info("Public Key:  {}", getPublicRsaKey());
    log.info("Private Key: {}", getPrivateRsaKey());
  }

  public RSAPublicKey getPublicRsaKey() {
    return publicRsaKey;
  }

  public RSAPrivateKey getPrivateRsaKey() {
    return privateRsaKey;
  }

}
