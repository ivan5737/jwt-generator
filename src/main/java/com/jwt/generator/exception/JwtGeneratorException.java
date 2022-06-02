package com.jwt.generator.exception;

import com.jwt.generator.model.ErrorResponse;
import lombok.Getter;
import org.springframework.http.HttpStatus;

public class JwtGeneratorException extends RuntimeException {

  private static final long serialVersionUID = -79187800485143043L;

  @Getter
  private final ErrorResponse errorResponse;

  public JwtGeneratorException(String message, String locationError) {
    super(message);
    this.errorResponse = ErrorResponse.builder().errorCause(HttpStatus.INTERNAL_SERVER_ERROR)
        .code(String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR.value())).details(message)
        .location(locationError).build();
  }
}
