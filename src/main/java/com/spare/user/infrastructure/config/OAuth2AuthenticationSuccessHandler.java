package com.spare.user.infrastructure.config;

import com.spare.common.security.JwtUtil;
import com.spare.user.domain.User;
import com.spare.user.infrastructure.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthenticationSuccessHandler.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // JWT 토큰을 저장할 쿠키 이름
    private static final String JWT_COOKIE_NAME = "jwt_token";
    // 쿠키 만료 시간 (1일 = 86400초)
    private static final int COOKIE_MAX_AGE = 86400;

    public OAuth2AuthenticationSuccessHandler(UserRepository userRepository,
                                              @Lazy PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        logger.info("OAuth2 authentication successful, processing JWT token creation");

        try {
            if (authentication instanceof OAuth2AuthenticationToken) {
                OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
                OAuth2User oAuth2User = oauthToken.getPrincipal();

                if (oAuth2User == null) {
                    logger.error("OAuth2 user principal is null");
                    response.sendRedirect("/users/login?error=oauth2_user_null");
                    return;
                }

                // OAuth2User에서 이메일 정보 추출
                String email = oAuth2User.getAttribute("email");
                if (email == null) {
                    logger.error("Email not found in OAuth2 user attributes");
                    response.sendRedirect("/users/login?error=oauth2_email_missing");
                    return;
                }

                // 기존 사용자인지 확인하고 없으면 새로 생성
                User user = userRepository.findByEmail(email).orElse(null);
                if (user == null) {
                    // OAuth2 사용자만을 나타내는 특별한 패스워드 설정
                    String oauthPassword = passwordEncoder.encode("OAUTH2_PROVIDER_" + System.currentTimeMillis());

                    user = new User(email, oauthPassword, "USER");
                    user = userRepository.save(user);
                    logger.info("New OAuth2 user created: {}", email);
                } else {
                    logger.info("Existing OAuth2 user logged in: {}", email);
                }

                // JWT 토큰 생성 (UserService의 로직을 직접 구현)
                String token = JwtUtil.generateToken(user.getEmail(), user.getRole());

                // HttpOnly 쿠키 생성 및 설정
                Cookie jwtCookie = new Cookie(JWT_COOKIE_NAME, token);
                jwtCookie.setHttpOnly(true);  // XSS 공격 방지
                jwtCookie.setSecure(false);   // HTTPS에서만 전송 (개발환경에서는 false)
                jwtCookie.setPath("/");       // 모든 경로에서 쿠키 전송
                jwtCookie.setMaxAge(COOKIE_MAX_AGE);  // 쿠키 만료 시간 설정
                jwtCookie.setAttribute("SameSite", "Lax");  // CSRF 공격 방지

                response.addCookie(jwtCookie);
                logger.info("JWT token successfully set in HttpOnly cookie for OAuth2 user: {}", email);

                // 성공 페이지로 리다이렉트
                response.sendRedirect("/users/welcome");

            } else {
                logger.error("Authentication is not OAuth2AuthenticationToken: {}", authentication.getClass());
                response.sendRedirect("/users/login?error=oauth2_token_invalid");
            }

        } catch (Exception e) {
            logger.error("Error during OAuth2 authentication success handling: {}", e.getMessage(), e);
            response.sendRedirect("/users/login?error=oauth2_processing_failed");
        }
    }
}