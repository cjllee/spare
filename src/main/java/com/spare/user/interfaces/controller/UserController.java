package com.spare.user.interfaces.controller;

import com.spare.user.application.UserService;
import com.spare.user.interfaces.dto.UserDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@Tag(name = "사용자 API", description = "회원가입, 로그인, 인증 관련 API")
public class UserController {
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final UserService userService;

    private static final String JWT_COOKIE_NAME = "jwt_token";
    private static final int COOKIE_MAX_AGE = 86400;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    @Operation(summary = "현재 사용자 상태 확인")
    public ResponseEntity<?> getCurrentUser(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return ResponseEntity.ok("Already logged in");
        }
        return ResponseEntity.status(401).body("Not authenticated");
    }

    @PostMapping("/verification/send")
    @Operation(summary = "이메일 인증 코드 발송", description = "회원가입용 이메일 인증 코드를 발송합니다")
    public ResponseEntity<String> sendVerificationCode(@RequestBody UserDto userDto, Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return ResponseEntity.badRequest().body("Already logged in. Please logout first.");
        }

        userService.sendVerificationCode(userDto);
        return ResponseEntity.ok("Verification code sent");
    }

    @PostMapping("/verification/verify")
    @Operation(summary = "인증 코드 확인", description = "이메일로 받은 인증 코드를 확인합니다")
    public ResponseEntity<String> verifyCode(@RequestParam String email, @RequestParam String code, Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return ResponseEntity.badRequest().body("Already logged in. Please logout first.");
        }

        if (userService.verifyCode(email, code)) {
            return ResponseEntity.ok("Verification successful");
        }
        return ResponseEntity.badRequest().body("Verification failed");
    }

    @PostMapping("/signup")
    @Operation(summary = "회원가입", description = "이메일 인증 완료 후 회원가입을 진행합니다")
    public ResponseEntity<UserDto> signup(@RequestBody UserDto userDto, Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return ResponseEntity.badRequest().body(null);
        }

        UserDto savedUser = userService.signup(userDto);
        return ResponseEntity.ok(savedUser);
    }

    @PostMapping("/login")
    @Operation(summary = "로그인", description = "이메일과 비밀번호로 로그인하여 JWT 토큰을 HttpOnly 쿠키에 저장합니다")
    public ResponseEntity<String> login(@RequestBody UserDto userDto, HttpServletResponse response) {
        try {
            String token = userService.login(userDto);

            // HttpOnly 쿠키 생성
            Cookie jwtCookie = new Cookie(JWT_COOKIE_NAME, token);
            jwtCookie.setHttpOnly(true);  // XSS 공격 방지
            jwtCookie.setSecure(false);   // HTTPS에서만 전송 (개발환경에서는 false)
            jwtCookie.setPath("/");       // 모든 경로에서 쿠키 전송
            jwtCookie.setMaxAge(COOKIE_MAX_AGE);  // 쿠키 만료 시간 설정
            jwtCookie.setAttribute("SameSite", "Lax");  // CSRF 공격 방지

            response.addCookie(jwtCookie);
            logger.info("JWT token set in HttpOnly cookie for user login");

            return ResponseEntity.ok("Login successful");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/logout")
    @Operation(summary = "로그아웃", description = "JWT 토큰 쿠키를 삭제하여 로그아웃합니다")
    public ResponseEntity<String> logout(HttpServletResponse response) {
        // JWT 쿠키 삭제
        Cookie jwtCookie = new Cookie(JWT_COOKIE_NAME, null);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setSecure(false);
        jwtCookie.setPath("/");
        jwtCookie.setMaxAge(0);  // 즉시 만료

        response.addCookie(jwtCookie);
        logger.info("JWT token cookie deleted for logout");

        return ResponseEntity.ok("Logout successful");
    }
}