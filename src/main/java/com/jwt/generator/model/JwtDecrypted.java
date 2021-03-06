package com.jwt.generator.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class JwtDecrypted {

  private String jwt;

  private String keyId;

}
