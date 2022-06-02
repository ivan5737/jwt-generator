package com.jwt.generator.exception;

import com.jwt.generator.model.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class ExceptionHandlerAdvice {

  @ExceptionHandler(Exception.class)
  public final ResponseEntity<Object> handleAllExceptions(Exception exception) {
    ErrorResponse errorResponse = ErrorResponse.builder()
        .errorCause(HttpStatus.INTERNAL_SERVER_ERROR).details(exception.getMessage())
        .code(String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR.value())).build();
    log.error("type{},code={},message={}", errorResponse.getErrorCause(), errorResponse.getCode(),
        errorResponse.getDetails(), exception);
    return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
  }

  @ExceptionHandler(JwtGeneratorException.class)
  public final ResponseEntity<Object> handleBookingExceptions(
      JwtGeneratorException jwtGeneratorException) {
    return new ResponseEntity<>(jwtGeneratorException.getErrorResponse(),
        HttpStatus.INTERNAL_SERVER_ERROR);
  }

}
