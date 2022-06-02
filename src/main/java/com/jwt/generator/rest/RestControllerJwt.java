package com.jwt.generator.rest;

import com.jwt.generator.model.JwtData;
import com.jwt.generator.model.JwtDecrypted;
import com.jwt.generator.model.RSAdata;
import com.jwt.generator.service.ServiceJwt;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/serviceJwt")
@RequiredArgsConstructor
public class RestControllerJwt {

  private final ServiceJwt serviceJwt;

  @GetMapping(value = "/generatePublicKey", produces = MediaType.APPLICATION_JSON_VALUE)
  public @ResponseBody RSAdata generatePublicKey() {
    return serviceJwt.generateKeys();
  }

  @PostMapping(value = "/generateJwt", produces = MediaType.APPLICATION_JSON_VALUE)
  public @ResponseBody JwtDecrypted generateJwt(@RequestBody RSAdata rsaData) {
    return serviceJwt.generateJwt(rsaData);
  }
  
  @PostMapping(value = "/decrytpJwt", produces = MediaType.APPLICATION_JSON_VALUE)
  public @ResponseBody JwtData decrytpJwt(@RequestBody JwtDecrypted jwtDecrypted) {
    return serviceJwt.decryptJwt(jwtDecrypted);
  }

}
