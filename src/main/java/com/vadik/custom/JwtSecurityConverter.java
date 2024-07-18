package com.vadik.custom;

import com.vadik.token.Token;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.function.Function;
import java.util.stream.Stream;

public class JwtSecurityConverter implements AuthenticationConverter {

    private static final String COOKIE_HEADER = "host-auth-token";
    private static final RequestMatcher LOGIN_REQUEST_MATCHER = new AntPathRequestMatcher("/Login", "POST");
    private Function<String, Token> tokenDeserializer;

    public JwtSecurityConverter(Function<String, Token> tokenDeserializer) {
        this.tokenDeserializer = tokenDeserializer;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        var cookies = request.getCookies();
        if(cookies != null && !this.LOGIN_REQUEST_MATCHER.matches(request)){
            return Stream.of(cookies)
                    .filter(cookie -> cookie.getName().equals(COOKIE_HEADER))
                    .findFirst()
                    .map(cookie -> {
                        var token = this.tokenDeserializer.apply(cookie.getValue());
                        return new PreAuthenticatedAuthenticationToken(token, cookie.getValue());
                    })
                    .orElse(null);
        }
        return null;
    }
}
