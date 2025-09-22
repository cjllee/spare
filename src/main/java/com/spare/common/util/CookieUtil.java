package com.spare.common.util;

import com.spare.common.constants.SecurityConstants;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

@Component
public class CookieUtil {

    /**
     * 액세스 토큰 쿠키 설정
     */
    public void setAccessTokenCookie(HttpServletResponse response, String token) {
        Cookie accessTokenCookie = createCookie(
                SecurityConstants.JWT_COOKIE_NAME,
                token,
                SecurityConstants.ACCESS_TOKEN_COOKIE_MAX_AGE
        );
        response.addCookie(accessTokenCookie);
    }

    /**
     * 리프레시 토큰 쿠키 설정
     */
    public void setRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie refreshTokenCookie = createCookie(
                SecurityConstants.REFRESH_COOKIE_NAME,
                refreshToken,
                SecurityConstants.REFRESH_TOKEN_COOKIE_MAX_AGE
        );
        response.addCookie(refreshTokenCookie);
    }

    /**
     * 두 토큰을 모두 설정
     */
    public void setTokenCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        setAccessTokenCookie(response, accessToken);
        setRefreshTokenCookie(response, refreshToken);
    }

    /**
     * 액세스 토큰 쿠키 삭제
     */
    public void deleteAccessTokenCookie(HttpServletResponse response) {
        Cookie cookie = createCookie(SecurityConstants.JWT_COOKIE_NAME, null, 0);
        response.addCookie(cookie);
    }

    /**
     * 리프레시 토큰 쿠키 삭제
     */
    public void deleteRefreshTokenCookie(HttpServletResponse response) {
        Cookie cookie = createCookie(SecurityConstants.REFRESH_COOKIE_NAME, null, 0);
        response.addCookie(cookie);
    }

    /**
     * 모든 토큰 쿠키 삭제
     */
    public void deleteAllTokenCookies(HttpServletResponse response) {
        deleteAccessTokenCookie(response);
        deleteRefreshTokenCookie(response);
    }

    /**
     * 쿠키에서 액세스 토큰 추출
     */
    public String getAccessTokenFromCookies(Cookie[] cookies) {
        return getCookieValue(cookies, SecurityConstants.JWT_COOKIE_NAME);
    }

    /**
     * 쿠키에서 리프레시 토큰 추출
     */
    public String getRefreshTokenFromCookies(Cookie[] cookies) {
        return getCookieValue(cookies, SecurityConstants.REFRESH_COOKIE_NAME);
    }

    /**
     * 쿠키에서 JWT 토큰 추출 (기존 호환성 유지)
     */
    public String getJwtFromCookies(Cookie[] cookies) {
        return getAccessTokenFromCookies(cookies);
    }

    private Cookie createCookie(String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // 개발환경에서는 false, 운영환경에서는 true로 설정
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        cookie.setAttribute("SameSite", "Lax");
        return cookie;
    }

    private String getCookieValue(Cookie[] cookies, String cookieName) {
        if (cookies == null) return null;

        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}