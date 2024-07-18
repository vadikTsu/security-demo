package com.vadik.custom;

import com.vadik.token.Token;
import com.vadik.token.utils.TokenDeserializer;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.function.Function;
import java.util.stream.Stream;


/**
 * Converter is responsible for instantiating {@link Authentication} from {@link HttpServletRequest}.
 * This converter is intended to be utilized by {@link AuthenticationFilter}
 *
 * <p>Utilizes {@link TokenDeserializer} to deserialize string into {@link Token} from request's cookies</p>
 * <p>If request matches {@link JwtSecurityConverter#LOGIN_REQUEST_MATCHER} converter returns <code>null</code></p>
 * <p>In case of successfully deserialized token {@link PreAuthenticatedAuthenticationToken} is returned</p>
 *
 * @author Vadym Tsudenko
 */
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
