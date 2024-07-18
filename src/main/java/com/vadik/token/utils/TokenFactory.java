package com.vadik.token.utils;

import com.vadik.token.Token;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

public class TokenFactory implements Function<Authentication, Token> {

    private long durationSeconds = 20;

    @Override
    public Token apply(Authentication authentication) {
        return new Token(UUID.randomUUID(), ((UserDetails)authentication.getPrincipal()).getUsername(), authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()), Instant.now(), Instant.now().plusSeconds(this.durationSeconds));
    }

    public TokenFactory setDurationSeconds(long durationSeconds) {
        this.durationSeconds = durationSeconds;
        return this;
    }
}
