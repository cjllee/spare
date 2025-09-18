package com.spare.user.infrastructure.config;

import com.spare.common.security.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String JWT_COOKIE_NAME = "jwt_token";

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        boolean skip = path.startsWith("/oauth2/") || path.startsWith("/login/oauth2/") || path.equals("/api/users/oauth2/success");
        if (skip) {
            logger.debug("Skipping JWT filter for path: {}", path);
        }
        return skip;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        String token = null;

        // 1. Authorization 헤더에서 토큰 확인
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            token = header.replace("Bearer ", "");
            logger.debug("JWT token found in Authorization header for path: {}", path);
        }
        // 2. Authorization 헤더에 토큰이 없으면 쿠키에서 확인
        else {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (JWT_COOKIE_NAME.equals(cookie.getName())) {
                        token = cookie.getValue();
                        logger.debug("JWT token found in cookie for path: {}", path);
                        break;
                    }
                }
            }
        }

        // 토큰이 없으면 다음 필터로
        if (token == null) {
            logger.debug("No JWT token found in request headers or cookies for path: {}", path);
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰 검증 및 인증 설정
        try {
            String email = JwtUtil.getEmailFromToken(token);
            logger.debug("JWT token validated for email: {} on path: {}", email, path);

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    email, null, null);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            logger.error("JWT token validation failed for path: {}: {}", path, e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}