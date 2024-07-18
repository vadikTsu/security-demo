package com.vadik.custom;

import com.vadik.token.Token;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.time.Instant;
import java.util.List;


/**
 * Loads data about user from Cache or Data Source.
 * In this case "mock" Data Source/Cache is injected with simplicity purpose;
 */
public class PreAuthenticatedTokenDetailsService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private UserDetailsService dataSource;

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken authToken) throws UsernameNotFoundException {
        if (authToken.getPrincipal() instanceof Token) {
            UserDetails userDetails = dataSource.loadUserByUsername(((Token) authToken.getPrincipal()).subject());
            return new User(userDetails.getUsername(),
                    "nopassword",
                    true, true,
                    ((Token) authToken.getPrincipal()).expiresAt().isAfter(Instant.now()),
                    true, userDetails.getAuthorities());
        }
        throw new UsernameNotFoundException("Invalid Token");
    }

    public PreAuthenticatedTokenDetailsService setDataSource(UserDetailsService dataSource) {
        this.dataSource = dataSource;
        return this;
    }
}
