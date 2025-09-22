package com.spare.common.security;

import com.spare.common.constants.SecurityConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Service
public class RefreshTokenService {
    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenService.class);

    private final RedisTemplate<String, Object> redisTemplate;
    private final JwtUtil jwtUtil;

    public RefreshTokenService(RedisTemplate<String, Object> redisTemplate, JwtUtil jwtUtil) {
        this.redisTemplate = redisTemplate;
        this.jwtUtil = jwtUtil;
    }

    /**
     * 리프레시 토큰을 Redis에 저장
     */
    public void storeRefreshToken(String email, String refreshToken) {
        try {
            String key = SecurityConstants.REFRESH_TOKEN_PREFIX + email;
            String jti = jwtUtil.getJtiFromToken(refreshToken);

            // 기존 리프레시 토큰이 있으면 삭제
            redisTemplate.delete(key);

            // 새로운 리프레시 토큰 저장
            redisTemplate.opsForValue().set(
                    key,
                    jti,
                    Duration.ofMillis(jwtUtil.getRefreshTokenExpiration())
            );

            logger.info("리프레시 토큰 저장 완료: {}", email);
        } catch (Exception e) {
            logger.error("리프레시 토큰 저장 실패: {}", e.getMessage(), e);
            throw new RuntimeException("리프레시 토큰 저장에 실패했습니다", e);
        }
    }

    /**
     * 리프레시 토큰 유효성 검증
     */
    public boolean isValidRefreshToken(String email, String refreshToken) {
        try {
            if (!jwtUtil.isTokenValid(refreshToken) || !jwtUtil.isRefreshToken(refreshToken)) {
                logger.debug("유효하지 않은 리프레시 토큰: {}", email);
                return false;
            }

            String key = SecurityConstants.REFRESH_TOKEN_PREFIX + email;
            String storedJti = (String) redisTemplate.opsForValue().get(key);
            String tokenJti = jwtUtil.getJtiFromToken(refreshToken);

            boolean isValid = storedJti != null && storedJti.equals(tokenJti);

            if (!isValid) {
                logger.warn("리프레시 토큰 JTI 불일치: {}", email);
            }

            return isValid;
        } catch (Exception e) {
            logger.error("리프레시 토큰 검증 실패: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 리프레시 토큰 삭제 (로그아웃 시)
     */
    public void revokeRefreshToken(String email) {
        try {
            String key = SecurityConstants.REFRESH_TOKEN_PREFIX + email;
            redisTemplate.delete(key);
            logger.info("리프레시 토큰 삭제 완료: {}", email);
        } catch (Exception e) {
            logger.error("리프레시 토큰 삭제 실패: {}", e.getMessage(), e);
        }
    }

    /**
     * 특정 사용자의 모든 리프레시 토큰 삭제
     */
    public void revokeAllRefreshTokens(String email) {
        revokeRefreshToken(email);
    }

    /**
     * 만료된 리프레시 토큰 정리 (스케줄링으로 호출)
     */
    public void cleanupExpiredTokens() {
        try {
            // Redis에서 TTL이 만료된 키들은 자동으로 삭제되므로 별도 작업 불필요
            logger.debug("만료된 리프레시 토큰 정리 완료");
        } catch (Exception e) {
            logger.error("만료된 리프레시 토큰 정리 실패: {}", e.getMessage(), e);
        }
    }

    /**
     * 리프레시 토큰의 남은 만료 시간 확인
     */
    public long getRefreshTokenTTL(String email) {
        try {
            String key = SecurityConstants.REFRESH_TOKEN_PREFIX + email;
            return redisTemplate.getExpire(key, TimeUnit.SECONDS);
        } catch (Exception e) {
            logger.error("리프레시 토큰 TTL 확인 실패: {}", e.getMessage(), e);
            return -1;
        }
    }
}