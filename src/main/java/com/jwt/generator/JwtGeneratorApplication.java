package com.jwt.generator;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class JwtGeneratorApplication {

  public static void main(String[] args) {
    SpringApplication.run(JwtGeneratorApplication.class, args);
  }

}
