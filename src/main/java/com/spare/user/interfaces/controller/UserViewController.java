package com.spare.user.interfaces.controller;

import com.spare.user.application.UserService;
import com.spare.user.interfaces.dto.UserDto;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/users")
public class UserViewController {
    private static final Logger logger = LoggerFactory.getLogger(UserViewController.class);
    private final UserService userService;

    // JWT 토큰을 저장할 쿠키 이름
    private static final String JWT_COOKIE_NAME = "jwt_token";
    // 쿠키 만료 시간 (1일 = 86400초)
    private static final int COOKIE_MAX_AGE = 86400;

    public UserViewController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/signup")
    public String showSignupForm(Model model) {
        model.addAttribute("userDto", new UserDto());
        return "signup";
    }

    @PostMapping("/verification/send")
    public String sendVerificationCode(@ModelAttribute UserDto userDto, Model model) {
        try {
            userService.sendVerificationCode(userDto);
            model.addAttribute("successMessage", "인증 코드가 발송되었습니다.");
            model.addAttribute("email", userDto.getEmail());
            logger.info("Verification code sent to: {}", userDto.getEmail());
        } catch (IllegalArgumentException e) {
            model.addAttribute("errorMessage", e.getMessage());
            model.addAttribute("userDto", userDto);
            logger.warn("Failed to send verification code: {}", e.getMessage());
        }
        return "signup";
    }

    @PostMapping("/verification/verify")
    public String verifyCode(@RequestParam String email, @RequestParam String code, Model model) {
        try {
            if (userService.verifyCode(email, code)) {
                model.addAttribute("successMessage", "인증이 완료되었습니다.");
                model.addAttribute("email", email);
                logger.info("Verification successful for email: {}", email);
            } else {
                model.addAttribute("errorMessage", "인증 코드가 잘못되었습니다.");
                model.addAttribute("email", email);
                logger.warn("Verification failed for email: {}", email);
            }
        } catch (Exception e) {
            model.addAttribute("errorMessage", "인증 처리 중 오류가 발생했습니다.");
            model.addAttribute("email", email);
            logger.error("Error during verification for email: {}: {}", email, e.getMessage());
        }
        model.addAttribute("userDto", new UserDto());
        return "signup";
    }

    @PostMapping("/signup")
    public String signup(@ModelAttribute UserDto userDto, Model model) {
        try {
            userService.signup(userDto);
            logger.info("User signed up successfully: {}", userDto.getEmail());
            return "redirect:/users/welcome";
        } catch (IllegalArgumentException e) {
            model.addAttribute("errorMessage", e.getMessage());
            model.addAttribute("email", userDto.getEmail());
            model.addAttribute("userDto", userDto);
            logger.warn("Signup failed for email: {}: {}", userDto.getEmail(), e.getMessage());
            return "signup";
        }
    }

    @GetMapping("/login")
    public String showLoginForm(Model model) {
        model.addAttribute("userDto", new UserDto());
        return "login";
    }

    @PostMapping("/login")
    public String login(@ModelAttribute UserDto userDto, Model model, HttpServletResponse response) {
        try {
            String token = userService.login(userDto);

            // JWT 쿠키 설정 (API Controller와 동일한 로직)
            Cookie jwtCookie = new Cookie(JWT_COOKIE_NAME, token);
            jwtCookie.setHttpOnly(true);  // XSS 공격 방지
            jwtCookie.setSecure(false);   // 개발환경에서는 false
            jwtCookie.setPath("/");       // 모든 경로에서 쿠키 전송
            jwtCookie.setMaxAge(COOKIE_MAX_AGE);  // 쿠키 만료 시간 설정
            jwtCookie.setAttribute("SameSite", "Lax");  // CSRF 공격 방지

            response.addCookie(jwtCookie);
            logger.info("User logged in successfully with JWT cookie: {}", userDto.getEmail());

            return "redirect:/users/welcome";
        } catch (IllegalArgumentException e) {
            model.addAttribute("errorMessage", "로그인 실패: " + e.getMessage());
            model.addAttribute("userDto", userDto);
            logger.warn("Login failed for email: {}: {}", userDto.getEmail(), e.getMessage());
            return "login";
        }
    }

    @GetMapping("/welcome")
    public String showWelcomePage() {
        return "welcome";
    }


}