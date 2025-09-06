package com.spare.user.application;

import com.spare.common.security.JwtUtil;
import com.spare.user.domain.User;
import com.spare.user.infrastructure.UserRepository;
import com.spare.user.interfaces.dto.UserDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public UserDto signup(UserDto userDto) {
        logger.info("Processing signup for email: {}", userDto.getEmail());
        if (userRepository.findByEmail(userDto.getEmail()).isPresent()) {
            logger.warn("Email already exists: {}", userDto.getEmail());
            throw new RuntimeException("Email already exists");
        }
        User user = new User(userDto.getEmail(), passwordEncoder.encode(userDto.getPassword()), userDto.getRole());
        User savedUser = userRepository.save(user);
        logger.debug("User saved with ID: {}", savedUser.getId());
        return new UserDto(savedUser.getId(), savedUser.getEmail(), null, savedUser.getRole(), savedUser.getCreatedAt());
    }

    public String login(UserDto userDto) {
        logger.info("Processing login for email: {}", userDto.getEmail());
        User user = userRepository.findByEmail(userDto.getEmail())
                .orElseThrow(() -> {
                    logger.warn("User not found: {}", userDto.getEmail());
                    return new RuntimeException("User not found");
                });
        if (!passwordEncoder.matches(userDto.getPassword(), user.getPassword())) {
            logger.warn("Invalid password for email: {}", userDto.getEmail());
            throw new RuntimeException("Invalid password");
        }
        String token = JwtUtil.generateToken(user.getEmail(), user.getRole());
        logger.debug("Login successful, JWT issued for email: {}", user.getEmail());
        return token;
    }

    public String loginWithOAuth2(OAuth2User oAuth2User) {
        String email = oAuth2User.getAttribute("email");
        logger.info("Processing OAuth2 login for email: {}", email);
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    logger.info("Creating new user for OAuth2 login: {}", email);
                    User newUser = new User(email, "oauth2-user", "USER");
                    return userRepository.save(newUser);
                });
        String token = JwtUtil.generateToken(user.getEmail(), user.getRole());
        logger.debug("OAuth2 login successful, JWT issued for email: {}", user.getEmail());
        return token;
    }
}