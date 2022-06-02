package com.jwt.generator.repository;

import com.jwt.generator.model.RsaData;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class PrivateKeyRepository {

  private final JdbcTemplate jdbcTemplate;

  /**
   * Method to save the RSA data in the DB.
   * 
   * @param rsaData that contains the private key values.
   * @return Integer value of the update method
   */
  public Integer savePrivateKeyInDb(RsaData rsaData) {
    Object[] params = {rsaData.getKeyId(), rsaData.getModulus(), rsaData.getExponent()};
    return jdbcTemplate.update("INSERT INTO privateKey VALUES (?,?,?)", params);
  }

  /**
   * Method to get the private key from the DB.
   * 
   * @param id of the private key, to find every private key
   * @return RsaData
   */
  public RsaData getPrivateKey(String id) {
    Object[] params = {id};
    return jdbcTemplate.queryForObject("SELECT * FROM privateKey WHERE id = ?",
        new BeanPropertyRowMapper<>(RsaData.class), params);
  }

}
