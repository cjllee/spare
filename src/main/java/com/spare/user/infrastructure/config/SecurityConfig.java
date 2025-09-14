package com.spare.user.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false))
                .authorizeHttpRequests(auth -> auth
                        // 인증 없이 접근 가능한 경로들
                        .requestMatchers(
                                "/api/users/signup",
                                "/api/users/login",
                                "/api/users/verification/send",
                                "/api/users/verification/verify",
                                "/users/login",           // 일반 로그인 페이지
                                "/users/signup",          // 일반 회원가입 페이지
                                "/login",                 // 로그인 페이지
                                "/signup",                // 회원가입 페이지
                                "/css/**",                // CSS 파일들
                                "/js/**",                 // JavaScript 파일들
                                "/images/**",             // 이미지 파일들
                                "/favicon.ico",           // 파비콘
                                "/error",                 // 에러 페이지
                                // Swagger UI 관련 경로들
                                "/swagger-ui/**",         // Swagger UI
                                "/v3/api-docs/**",        // OpenAPI 문서
                                "/swagger-ui.html",       // Swagger UI 메인 페이지
                                "/webjars/**"             // Swagger UI 리소스
                        ).permitAll()
                        // OAuth2 관련 경로들
                        .requestMatchers("/oauth2/**", "/login/oauth2/**").permitAll()
                        // OAuth2 성공 콜백
                        .requestMatchers("/api/users/oauth2/success").permitAll()
                        // 나머지는 인증 필요
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                                // OAuth2 로그인 시작 경로를 명시적으로 설정
                                .authorizationEndpoint(authorization -> authorization
                                        .baseUri("/oauth2/authorization"))
                                // OAuth2 로그인 성공 시 리다이렉트 URL
                                .defaultSuccessUrl("/api/users/oauth2/success", true)
                                // OAuth2 로그인 실패 시 리다이렉트 URL
                                .failureUrl("/login?error=oauth2_failed")
                        // 커스텀 로그인 페이지는 설정하지 않음 (자동 리다이렉트 방지)
                )
                // 폼 로그인 설정 (일반 로그인용)
                .formLogin(form -> form
                        .loginPage("/users/login")        // 일반 로그인 페이지
                        .loginProcessingUrl("/api/users/login")  // 로그인 처리 URL
                        .defaultSuccessUrl("/dashboard", true)
                        .failureUrl("/users/login?error=true")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/users/login?logout=true")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }
}