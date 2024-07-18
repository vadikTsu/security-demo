package com.vadik.token.utils;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.vadik.token.Token;

import java.sql.Date;
import java.util.function.Function;

public class TokenSerializer implements Function<Token, String> {

    private final JWEEncrypter jweEncrypter;

    private JWEAlgorithm jweAlgorithm = JWEAlgorithm.DIR;

    private EncryptionMethod encryptionMethod = EncryptionMethod.A256GCM;

    public TokenSerializer(JWEEncrypter jweEncrypter) {
        this.jweEncrypter = jweEncrypter;
    }

    @Override
    public String apply(Token token) {
        var jwsHeader = new JWEHeader.Builder(this.jweAlgorithm,this.encryptionMethod)
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

        try {
            jwtEncrypted.encrypt(this.jweEncrypter);
            return jwtEncrypted.serialize();
        } catch (JOSEException e) {
            System.err.println("ERROR  TokenSerializer");
        }
        return null;
    }
}
