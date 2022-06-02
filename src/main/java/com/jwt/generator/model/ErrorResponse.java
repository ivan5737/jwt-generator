package com.jwt.generator.model;

import lombok.Builder;
import lombok.Data;
import org.springframework.http.HttpStatus;

import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

@Data
@Builder
public class ErrorResponse implements Serializable {

  private static final long serialVersionUID = -5077517696150582558L;

  private String code;

  private String details;

  private String location;

  private HttpStatus errorCause;

  @Builder.Default
  private String uuid = new StringBuilder().append(UUID.randomUUID()).append("-")
      .append(System.currentTimeMillis()).toString();

  @Builder.Default
  private String timestamp = Instant.now().toString();

}
