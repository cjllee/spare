package com.spare.common.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.util.Date;

public class JwtUtil {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);
    private static final SecretKey SECRET_KEY = Jwts.SIG.HS512.key().build();
    private static final long EXPIRATION_TIME = 86400000; // 1일

    public static String generateToken(String email, String role) {
        String token = Jwts.builder()
                .subject(email)
                .claim("role", role)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY)
                .compact();
        return token;
    }

    public static String getEmailFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(SECRET_KEY)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            String email = claims.getSubject();
            return email;
        } catch (Exception e) {
            throw new RuntimeException("Invalid JWT token", e);
        }
    }
}