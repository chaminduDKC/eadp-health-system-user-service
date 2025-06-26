package com.hope_health.user_service.config;

import com.hope_health.user_service.util.JwtAuthConverter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthConverter jwtAuthConverter;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http
                .csrf()
                    .disable()
                .authorizeHttpRequests(requests -> requests
                            .requestMatchers("/api/users/register-patient").permitAll()
                            .requestMatchers("/api/users/patient-login").permitAll()
                            .requestMatchers("/api/users/admin-login").permitAll()
                            .requestMatchers("/api/users/login-doctor").permitAll()
                            .requestMatchers("/api/users/verify-user").permitAll()
                            .requestMatchers("/api/users/resend-otp").permitAll()
                            .anyRequest().authenticated()
                        );

//        http.cors(httpSecurityCorsConfigurer ->
//                httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource()));

        http.oauth2ResourceServer()
                .jwt()
                    .jwtAuthenticationConverter(jwtAuthConverter);


        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        return http.build();
    }

}
