package com.spare.common.util;

import com.spare.common.constants.SecurityConstants;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

@Component
public class CookieUtil {

    public void setJwtCookie(HttpServletResponse response, String token) {
        Cookie jwtCookie = createJwtCookie(token, SecurityConstants.COOKIE_MAX_AGE);
        response.addCookie(jwtCookie);
    }

    public void deleteJwtCookie(HttpServletResponse response) {
        Cookie jwtCookie = createJwtCookie(null, 0);
        response.addCookie(jwtCookie);
    }

    private Cookie createJwtCookie(String value, int maxAge) {
        Cookie cookie = new Cookie(SecurityConstants.JWT_COOKIE_NAME, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // 개발환경에서는 false, 운영환경에서는 true로 설정
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        cookie.setAttribute("SameSite", "Lax");
        return cookie;
    }

    public String getJwtFromCookies(Cookie[] cookies) {
        if (cookies == null) return null;

        for (Cookie cookie : cookies) {
            if (SecurityConstants.JWT_COOKIE_NAME.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}