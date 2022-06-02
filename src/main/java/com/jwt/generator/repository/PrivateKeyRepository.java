package com.jwt.generator.repository;

import com.jwt.generator.model.RSAdata;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class PrivateKeyRepository {

  private final JdbcTemplate jdbcTemplate;

  public Integer savePrivateKeyInDb(RSAdata rsaData) {
    Object[] params = {rsaData.getId(), rsaData.getModulus(), rsaData.getExponent()};
    return jdbcTemplate.update("INSERT INTO privateKey VALUES (?,?,?)", params);
  }

  public RSAdata getPrivateKey(String id) {
    Object[] params = {id};
    return jdbcTemplate.queryForObject("SELECT * FROM privateKey WHERE id = ?",
        new BeanPropertyRowMapper<RSAdata>(RSAdata.class), params);
  }

}
