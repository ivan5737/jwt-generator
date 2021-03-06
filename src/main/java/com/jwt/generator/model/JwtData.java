package com.jwt.generator.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

import java.util.Date;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class JwtData {

  private String issuer;

  private String subject;

  private Date expirationTime;

  private Date notBeforeTime;

  private String jwtId;

  private String appId;

  private String userId;

  private String role;

  private String applicationType;

  private String clientRemoteAddress;
  
  private String keyId;

}
