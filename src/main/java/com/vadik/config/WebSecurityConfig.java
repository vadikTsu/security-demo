package com.vadik.config;

import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.vadik.custom.JwtSecurityConverter;
import com.vadik.custom.OnAuthenticationSuccessStrategy;
import com.vadik.custom.PreAuthenticatedTokenDetailsService;
import com.vadik.token.Token;
import com.vadik.token.utils.TokenDeserializer;
import com.vadik.token.utils.TokenSerializer;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;


import java.security.Principal;
import java.util.Collections;
import java.util.List;

/**
 * Configures security concerns with HttpOnly cookie-based JWTs approach.
 */
@Configuration
@EnableWebSecurity(debug = true)
public class WebSecurityConfig {

    String key = "{\"k\": \"R+zGsNQr13neRPKAE3R986gyNwgxueTxsOTYsowavEY=\", \"kty\": \"oct\"}";


    @Bean
    public TokenDeserializer tokenDeserializer() throws Exception {
        return new TokenDeserializer(new DirectDecrypter(
                OctetSequenceKey.parse(key)));
    }

    @Bean
    public TokenSerializer tokenSerializer() throws Exception {
        return new TokenSerializer(new DirectEncrypter(
                OctetSequenceKey.parse(key)));
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)  //todo implement CSRF security (coming soon :D )
                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() { //creates anonymous class to configure CORS
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                        config.setAllowedMethods(Collections.singletonList("*"));
                        config.setAllowCredentials(true);
                        config.setAllowedHeaders(Collections.singletonList("*"));
                        config.setMaxAge(3600L);
                        return config;
                    }
                }))
                .authorizeHttpRequests(
                        request ->
                                request
                                        .requestMatchers("/protected").hasAuthority("USER")   //defines protected resource
                                        .anyRequest().permitAll()
                )
                .authenticationManager(authenticationManager())
                .httpBasic(Customizer.withDefaults());

        this.configureJwtBasedSecurity(httpSecurity);
        return httpSecurity.build();
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public UserDetailsService userDetailsService() {        //simple UserDetailsService to not complicate this draft
        return new InMemoryUserDetailsManager(
                new User("vadym", "qwer", List.of(new SimpleGrantedAuthority("USER")))
        );
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(daoAuthenticationProvider(),        //ProviderManager is chosen as AuthenticationManager
                preAuthenticatedAuthenticationProvider());             //Both available AuthProviders are injected into constructor parameters
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        var daoProvider = new DaoAuthenticationProvider(passwordEncoder());
        daoProvider.setUserDetailsService(userDetailsService());
        return daoProvider;
    }

    @Bean
    public PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider() {
        var preProvider = new PreAuthenticatedAuthenticationProvider();
        preProvider.setPreAuthenticatedUserDetailsService(
                new PreAuthenticatedTokenDetailsService().setDataSource(userDetailsService())   //setting PreAuthUsrDetailsSource
        );
        return preProvider;
    }


    /**
     * Configures {@link SecurityFilterChain} to incorporate JWTs approach in authentication workflow.
     *
     * <p>Sets {@link AuthenticationFilter} for {@link SecurityFilterChain} to perform authentication with
     * {@link PreAuthenticatedAuthenticationToken} which should carry {@link Token} as {@link Principal}.</p>
     * <p>
     * Also {@link AuthenticationFilter} incorporates {@link JwtSecurityConverter},
     * this converter is responsible for instantiating {@link PreAuthenticatedAuthenticationToken}.</p>
     * </p>
     * <p>
     * In case of invalid token {@link AuthenticationFailureHandler}
     * is set to return a response to client with 403 (forbidden status).
     * </p>
     *
     * <p>
     *     Session management configured to handle stateless sessions.
     *     Also {@link OnAuthenticationSuccessStrategy} is set as success strategy handler,
     *     which is triggered whenever successful authentication occurs.
     * </p>
     */
    private void configureJwtBasedSecurity(HttpSecurity builder) throws Exception {

        AuthenticationFilter authenticationFilter = new AuthenticationFilter(
                authenticationManager(),
                new JwtSecurityConverter(tokenDeserializer())
        );

        authenticationFilter.setSuccessHandler((request, response, authentication) -> {
        });
        authenticationFilter.setFailureHandler(
                new AuthenticationEntryPointFailureHandler(
                        new Http403ForbiddenEntryPoint()
                )
        );

        builder.sessionManagement(sessionManagement -> {
                    try {
                        sessionManagement
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                                .sessionAuthenticationStrategy(new OnAuthenticationSuccessStrategy(tokenSerializer()));
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .addFilterAfter(authenticationFilter, CsrfFilter.class);
    }
}
