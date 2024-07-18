package com.vadik.token.utils;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.vadik.token.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Date;
import java.util.function.Function;


/**
 * Serializes {@link Token} instance in encrypted JSON Web token.
 *
 * <p>
 * <a href="https://mvnrepository.com/artifact/com.nimbusds/nimbus-jose-jwt">Nimbus JWT+JOSE</a>
 * module is utilized for serialization.
 * </p>
 */
public class TokenSerializer implements Function<Token, String> {

    private final Logger LOGGER = LoggerFactory.getLogger(TokenSerializer.class);

    private final JWEEncrypter jweEncrypter;

    private final JWEAlgorithm jweAlgorithm = JWEAlgorithm.DIR;

    private final EncryptionMethod encryptionMethod = EncryptionMethod.A256GCM;

    public TokenSerializer(JWEEncrypter jweEncrypter) {
        this.jweEncrypter = jweEncrypter;
    }

    @Override
    public String apply(Token token) {
        try {
            var jwsHeader = new JWEHeader.Builder(this.jweAlgorithm, this.encryptionMethod)
                    .keyID(token.id().toString()).build();

            var jwsPayload = new JWTClaimsSet
                    .Builder()
                    .jwtID(token.id().toString())
                    .subject(token.subject())
                    .claim("authorities", token.authorities())
                    .issueTime(Date.from(token.createdAt()))
                    .expirationTime(Date.from(token.expiresAt()))
                    .build();

            var jwtEncrypted = new EncryptedJWT(jwsHeader, jwsPayload);
            jwtEncrypted.encrypt(this.jweEncrypter);
            return jwtEncrypted.serialize();
        } catch (Exception e) {
            LOGGER.error(String.format("Failed to serialize token: %s with message: %s",
                    token.toString(), e.getMessage()));
        }
        return null;
    }
}
