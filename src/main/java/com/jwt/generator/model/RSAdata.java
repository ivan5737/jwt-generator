package com.jwt.generator.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.math.BigInteger;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
@NoArgsConstructor(access = AccessLevel.PACKAGE)
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public final class RSAdata {

  private BigInteger modulus;

  private BigInteger exponent;
  
  private String id;

}
