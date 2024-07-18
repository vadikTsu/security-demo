package com.vadik.config;

import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.vadik.custom.JwtSecurityConverter;
import com.vadik.custom.OnAuthenticationSuccessStrategy;
import com.vadik.custom.PreAuthenticatedTokenDetailsService;
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
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;


import java.util.Collections;
import java.util.List;

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
                .csrf(AbstractHttpConfigurer::disable)
                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
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
                                        .requestMatchers("/protected").hasAuthority("USER")
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
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                new User("vadym", "qwer", List.of(new SimpleGrantedAuthority("USER")))
        );
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(daoAuthenticationProvider(),
                preAuthenticatedAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        var daoProvider =new DaoAuthenticationProvider(passwordEncoder());
        daoProvider.setUserDetailsService(userDetailsService());
        return daoProvider;
    }

    @Bean
    public PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider(){
        var preProvider = new PreAuthenticatedAuthenticationProvider();
        preProvider.setPreAuthenticatedUserDetailsService(
                new PreAuthenticatedTokenDetailsService()
        );
        return preProvider;
    }


    private void configureJwtBasedSecurity(HttpSecurity builder) throws Exception {

        AuthenticationFilter authenticationFilter = new AuthenticationFilter(
                authenticationManager(),
                new JwtSecurityConverter(tokenDeserializer())
        );

        authenticationFilter.setSuccessHandler((request, response, authentication) -> {});
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
