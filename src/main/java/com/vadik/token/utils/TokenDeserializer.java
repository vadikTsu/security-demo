package com.vadik.token.utils;

import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.vadik.token.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;
import java.util.function.Function;

/**
 * Deserializes JWTs token and instantiates {@link Token} with token's claims.
 *
 */
public class TokenDeserializer implements Function<String, Token> {

    private final Logger LOGGER = LoggerFactory.getLogger(TokenSerializer.class);

    private JWEDecrypter jweDecrypter;

    public TokenDeserializer(JWEDecrypter jweDecrypter) {
        this.jweDecrypter = jweDecrypter;
    }

    @Override
    public Token apply(String string) {
        try {
            var encryptedJWT = EncryptedJWT.parse(string);
            encryptedJWT.decrypt(this.jweDecrypter);
            var claimsSet = encryptedJWT.getJWTClaimsSet();
            return new Token(
                    UUID.fromString(claimsSet.getJWTID()),
                    claimsSet.getSubject(),
                    claimsSet.getStringListClaim("authorities"),
                    claimsSet.getIssueTime().toInstant(),
                    claimsSet.getExpirationTime().toInstant());
        } catch (Exception exception) {
            LOGGER.error(String.format("Failed to deserialize token: %s with message: %s", string, exception.getMessage()));
        }
        return null;
    }
}
