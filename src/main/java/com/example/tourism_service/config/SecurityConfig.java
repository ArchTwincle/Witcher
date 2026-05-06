package com.example.tourism_service.config;

import com.example.tourism_service.repository.UserSessionRepository;
import com.example.tourism_service.security.JwtAuthenticationFilter;
import com.example.tourism_service.security.JwtTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtTokenProvider tokenProvider;
    private final UserDetailsService userDetailsService;
    private final UserSessionRepository sessionRepository;

    public SecurityConfig(JwtTokenProvider tokenProvider,
                          UserDetailsService userDetailsService,
                          UserSessionRepository sessionRepository) {
        this.tokenProvider = tokenProvider;
        this.userDetailsService = userDetailsService;
        this.sessionRepository = sessionRepository;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/login", "/api/auth/refresh").permitAll()
                        .requestMatchers("/api/auth/register").hasAnyAuthority("ADMIN", "ROLE_ADMIN")

                        .requestMatchers("/api/licenses/create").hasAnyAuthority("ADMIN", "ROLE_ADMIN")
                        .requestMatchers("/api/licenses/activate").hasAnyAuthority("USER", "ADMIN", "ROLE_USER", "ROLE_ADMIN")
                        .requestMatchers("/api/licenses/check").hasAnyAuthority("USER", "ADMIN", "ROLE_USER", "ROLE_ADMIN")
                        .requestMatchers("/api/licenses/renew").hasAnyAuthority("USER", "ADMIN", "ROLE_USER", "ROLE_ADMIN")

                        .requestMatchers("/licenses").hasAnyAuthority("ADMIN", "ROLE_ADMIN")
                        .requestMatchers("/licenses/**").hasAnyAuthority("USER", "ADMIN", "ROLE_USER", "ROLE_ADMIN")

                        .requestMatchers(HttpMethod.GET, "/api/tours/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/tours/**").hasAnyAuthority("ADMIN", "GUIDE", "ROLE_ADMIN", "ROLE_GUIDE")

                        .anyRequest().authenticated()
                );

        http.addFilterBefore(
                new JwtAuthenticationFilter(tokenProvider, userDetailsService, sessionRepository),
                UsernamePasswordAuthenticationFilter.class
        );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}