package com.spare.user.interfaces.controller;

import com.spare.user.application.UserService;
import com.spare.user.interfaces.dto.UserDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/verification/send")
    public ResponseEntity<String> sendVerificationCode(@RequestBody UserDto userDto) {
        userService.sendVerificationCode(userDto);
        return ResponseEntity.ok("Verification code sent");
    }

    @PostMapping("/verification/verify")
    public ResponseEntity<String> verifyCode(@RequestParam String email, @RequestParam String code) {
        if (userService.verifyCode(email, code)) {
            return ResponseEntity.ok("Verification successful");
        }
        return ResponseEntity.badRequest().body("Verification failed");
    }

    @PostMapping("/signup")
    public ResponseEntity<UserDto> signup(@RequestBody UserDto userDto) {
        UserDto savedUser = userService.signup(userDto);
        return ResponseEntity.ok(savedUser);
    }

    @GetMapping("/oauth2/success")
    public ResponseEntity<String> oauth2Login(OAuth2AuthenticationToken authentication) {
        // authentication이 null인지 확인
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