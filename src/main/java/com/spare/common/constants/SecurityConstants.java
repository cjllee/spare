package com.spare.common.constants;

public final class SecurityConstants {
    // JWT 토큰 관련
    public static final String JWT_COOKIE_NAME = "jwt_token";
    public static final String REFRESH_COOKIE_NAME = "refresh_token";
    public static final int ACCESS_TOKEN_COOKIE_MAX_AGE = 1800; // 30분
    public static final int REFRESH_TOKEN_COOKIE_MAX_AGE = 604800; // 7일
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String AUTHORIZATION_HEADER = "Authorization";

    // 권한
    public static final String ROLE_USER = "USER";
    public static final String ROLE_ADMIN = "ADMIN";

    // OAuth2
    public static final String OAUTH2_PASSWORD_PREFIX = "OAUTH2_PROVIDER_";

    // Redis 키 프리픽스
    public static final String REFRESH_TOKEN_PREFIX = "refresh_token:";

    private SecurityConstants() {
        // 인스턴스 생성 방지
    }
}