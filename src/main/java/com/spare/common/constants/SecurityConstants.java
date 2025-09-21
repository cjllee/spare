package com.spare.common.constants;

public final class SecurityConstants {
    public static final String JWT_COOKIE_NAME = "jwt_token";
    public static final int COOKIE_MAX_AGE = 86400; // 1일
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String AUTHORIZATION_HEADER = "Authorization";

    // 권한
    public static final String ROLE_USER = "USER";
    public static final String ROLE_ADMIN = "ADMIN";

    // OAuth2
    public static final String OAUTH2_PASSWORD_PREFIX = "OAUTH2_PROVIDER_";

    private SecurityConstants() {
        // 인스턴스 생성 방지
    }
}