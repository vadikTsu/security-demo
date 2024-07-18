package com.vadik.custom;

import com.vadik.token.Token;
import com.vadik.token.utils.TokenFactory;
import com.vadik.token.utils.TokenSerializer;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.time.Duration;
import java.util.function.Function;

public class OnAuthenticationSuccessStrategy implements SessionAuthenticationStrategy {


    private final Function<Authentication, Token> tokenFactory = new TokenFactory();

    private final TokenSerializer tokenSerializer;


    private static final String COOKIE_HEADER = "host-auth-token";


    public OnAuthenticationSuccessStrategy(TokenSerializer tokenSerializer) {
        this.tokenSerializer = tokenSerializer;
    }


    @Override
    public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response)
            throws SessionAuthenticationException {
        if (authentication instanceof UsernamePasswordAuthenticationToken){
            var token =this.tokenFactory.apply(authentication);
            var cookie = new Cookie(COOKIE_HEADER, tokenSerializer.apply(token));
            cookie.setPath("/");
            cookie.setDomain(null);
            cookie.setSecure(true);
            cookie.setHttpOnly(true);
            cookie.setMaxAge(Duration.between(token.expiresAt(),token.createdAt()).toSecondsPart());
            response.addCookie(cookie);
        }
    }
}
