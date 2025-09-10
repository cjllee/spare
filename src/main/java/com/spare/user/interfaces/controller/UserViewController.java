package com.spare.user.interfaces.controller;

import com.spare.user.application.UserService;
import com.spare.user.interfaces.dto.UserDto;
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
            return "redirect:/users/login";
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
    public String login(@ModelAttribute UserDto userDto, Model model) {
        try {
            String token = userService.login(userDto);
            model.addAttribute("successMessage", "로그인 성공! JWT: " + token);
            logger.info("User logged in successfully: {}", userDto.getEmail());
            return "login"; // 실제로는 홈으로 리다이렉트 예정
        } catch (IllegalArgumentException e) {
            model.addAttribute("errorMessage", "로그인 실패: " + e.getMessage());
            model.addAttribute("userDto", userDto);
            logger.warn("Login failed for email: {}: {}", userDto.getEmail(), e.getMessage());
            return "login";
        }
    }
}