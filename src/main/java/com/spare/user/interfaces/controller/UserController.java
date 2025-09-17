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
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@Tag(name = "ì‚¬ìš©ìž API", description = "íšŒì›ê°€ìž…, ë¡œê·¸ì¸, ì¸ì¦ ê´€ë ¨ API")
public class UserController {
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final UserService userService;


    private static final String JWT_COOKIE_NAME = "jwt_token";

    private static final int COOKIE_MAX_AGE = 86400;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    @Operation(summary = "í˜„ìž¬ ì‚¬ìš©ìž ìƒíƒœ í™•ì¸")
    public ResponseEntity<?> getCurrentUser(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return ResponseEntity.ok("Already logged in");
        }
        return ResponseEntity.status(401).body("Not authenticated");
    }

    @PostMapping("/verification/send")
    @Operation(summary = "ì´ë©”ì¼ ì¸ì¦ ì½”ë“œ ë°œì†¡", description = "íšŒì›ê°€ìž…ìš© ì´ë©”ì¼ ì¸ì¦ ì½”ë“œë¥¼ ë°œì†¡í•©ë‹ˆë‹¤")
    public ResponseEntity<String> sendVerificationCode(@RequestBody UserDto userDto, Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return ResponseEntity.badRequest().body("Already logged in. Please logout first.");
        }

        userService.sendVerificationCode(userDto);
        return ResponseEntity.ok("Verification code sent");
    }

    @PostMapping("/verification/verify")
    @Operation(summary = "ì¸ì¦ ì½”ë“œ í™•ì¸", description = "ì´ë©”ì¼ë¡œ ë°›ì€ ì¸ì¦ ì½”ë“œë¥¼ í™•ì¸í•©ë‹ˆë‹¤")
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
    @Operation(summary = "íšŒì›ê°€ìž…", description = "ì´ë©”ì¼ ì¸ì¦ ì™„ë£Œ í›„ íšŒì›ê°€ìž…ì„ ì§„í–‰í•©ë‹ˆë‹¤")
    public ResponseEntity<UserDto> signup(@RequestBody UserDto userDto, Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return ResponseEntity.badRequest().body(null);
        }

        UserDto savedUser = userService.signup(userDto);
        return ResponseEntity.ok(savedUser);
    }

    @PostMapping("/login")
    @Operation(summary = "ë¡œê·¸ì¸", description = "ì´ë©”ì¼ê³¼ ë¹„ë°€ë²ˆí˜¸ë¡œ ë¡œê·¸ì¸í•˜ì—¬ JWT í† í°ì„ HttpOnly ì¿ í‚¤ì— ì €ìž¥í•©ë‹ˆë‹¤")
    public ResponseEntity<String> login(@RequestBody UserDto userDto, HttpServletResponse response) {
        try {
            String token = userService.login(userDto);

            // HttpOnly ì¿ í‚¤ ìƒì„±
            Cookie jwtCookie = new Cookie(JWT_COOKIE_NAME, token);
            jwtCookie.setHttpOnly(true);  // XSS ê³µê²© ë°©ì§€
            jwtCookie.setSecure(false);   // HTTPSì—ì„œë§Œ ì „ì†¡ (ê°œë°œí™˜ê²½ì—ì„œëŠ” false)
            jwtCookie.setPath("/");       // ëª¨ë“  ê²½ë¡œì—ì„œ ì¿ í‚¤ ì „ì†¡
            jwtCookie.setMaxAge(COOKIE_MAX_AGE);  // ì¿ í‚¤ ë§Œë£Œ ì‹œê°„ ì„¤ì •
            jwtCookie.setAttribute("SameSite", "Lax");  // CSRF ê³µê²© ë°©ì§€

            response.addCookie(jwtCookie);
            logger.info("JWT token set in HttpOnly cookie for user login");

            return ResponseEntity.ok("Login successful");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/oauth2/success")
    @Operation(summary = "OAuth2 ë¡œê·¸ì¸ ì„±ê³µ", description = "Google OAuth2 ë¡œê·¸ì¸ ì„±ê³µ í›„ JWT í† í°ì„ HttpOnly ì¿ í‚¤ì— ì €ìž¥í•©ë‹ˆë‹¤")
    public ResponseEntity<String> oauth2Login(OAuth2AuthenticationToken authentication, HttpServletResponse response) {
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

            // HttpOnly ì¿ í‚¤ ìƒì„±
            Cookie jwtCookie = new Cookie(JWT_COOKIE_NAME, token);
            jwtCookie.setHttpOnly(true);  // XSS ê³µê²© ë°©ì§€
            jwtCookie.setSecure(false);   // HTTPSì—ì„œë§Œ ì „ì†¡ (ê°œë°œí™˜ê²½ì—ì„œëŠ” false)
            jwtCookie.setPath("/");       // ëª¨ë“  ê²½ë¡œì—ì„œ ì¿ í‚¤ ì „ì†¡
            jwtCookie.setMaxAge(COOKIE_MAX_AGE);  // ì¿ í‚¤ ë§Œë£Œ ì‹œê°„ ì„¤ì •
            jwtCookie.setAttribute("SameSite", "Lax");  // CSRF ê³µê²© ë°©ì§€

            response.addCookie(jwtCookie);
            logger.info("JWT token set in HttpOnly cookie for OAuth2 login");

            return ResponseEntity.ok("OAuth2 login successful");

        } catch (Exception e) {
            logger.error("OAuth2 login failed: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body("OAuth2 login failed: " + e.getMessage());
        }
    }



    @PostMapping("/logout")
    @Operation(summary = "ë¡œê·¸ì•„ì›ƒ", description = "JWT í† í° ì¿ í‚¤ë¥¼ ì‚­ì œí•˜ì—¬ ë¡œê·¸ì•„ì›ƒí•©ë‹ˆë‹¤")
    public ResponseEntity<String> logout(HttpServletResponse response) {
        // JWT ì¿ í‚¤ ì‚­ì œ
        Cookie jwtCookie = new Cookie(JWT_COOKIE_NAME, null);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setSecure(false);
        jwtCookie.setPath("/");
        jwtCookie.setMaxAge(0);  // ì¦‰ì‹œ ë§Œë£Œ

        response.addCookie(jwtCookie);
        logger.info("JWT token cookie deleted for logout");

        return ResponseEntity.ok("Logout successful");
    }
}