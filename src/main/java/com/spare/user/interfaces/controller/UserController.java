package com.spare.user.interfaces.controller;

import com.spare.user.application.UserService;
import com.spare.user.interfaces.dto.UserDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@Tag(name = "사용자 API", description = "회원가입, 로그인, 인증 관련 API")
public class UserController {
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final UserService userService;

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
    @Operation(summary = "로그인", description = "이메일과 비밀번호로 로그인하여 JWT 토큰을 발급받습니다")
    public ResponseEntity<String> login(@RequestBody UserDto userDto) {
        try {
            String token = userService.login(userDto);
            return ResponseEntity.ok(token);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/oauth2/success")
    @Operation(summary = "OAuth2 로그인 성공", description = "Google OAuth2 로그인 성공 후 JWT 토큰을 발급합니다")
    public ResponseEntity<String> oauth2Login(OAuth2AuthenticationToken authentication) {
        logger.warn("OAuth2 success endpoint called directly; redirect should occur via SecurityConfig to /users/welcome");
        if (authentication == null) {
            logger.error("OAuth2 authentication is null");
            return ResponseEntity.badRequest().body("Authentication failed: No authentication token found");
        }

        try {
            OAuth2User oAuth2User = authentication.getPrincipal();
            if (oAuth2User == null) {
                logger.error("OAuth2 user principal is null");
                return ResponseEntity.badRequest().body("Authentication failed: No user principal found");
            }

            String token = userService.loginWithOAuth2(oAuth2User);
            return ResponseEntity.ok(token);

        } catch (Exception e) {
            logger.error("OAuth2 login failed: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body("OAuth2 login failed: " + e.getMessage());
        }
    }
}