package com.spare.user.application;

import com.spare.common.util.EmailUtil;
import com.spare.user.domain.User;
import com.spare.user.infrastructure.UserRepository;
import com.spare.user.interfaces.dto.UserDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

@Service
public class UserService {
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailUtil emailUtil;
    private final RedisTemplate<String, Object> redisTemplate;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, EmailUtil emailUtil, RedisTemplate<String, Object> redisTemplate) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailUtil = emailUtil;
        this.redisTemplate = redisTemplate;
    }

    public void sendVerificationCode(UserDto userDto) {
        if (userRepository.existsByEmail(userDto.getEmail())) {
            logger.warn("Email already exists: {}", userDto.getEmail());
            throw new IllegalArgumentException("Email already exists");
        }
        String code = UUID.randomUUID().toString().substring(0, 6);
        redisTemplate.opsForValue().set("verification:" + userDto.getEmail(), code, Duration.ofMinutes(10));
        emailUtil.sendVerificationCode(userDto.getEmail(), code);
        logger.info("Verification code sent to: {}", userDto.getEmail());
    }

    public boolean verifyCode(String email, String code) {
        String storedCode = (String) redisTemplate.opsForValue().get("verification:" + email);
        if (storedCode != null && storedCode.equals(code)) {
            redisTemplate.delete("verification:" + email);
            logger.info("Verification successful for email: {}", email);
            return true;
        }
        logger.warn("Verification failed for email: {}", email);
        return false;
    }

    public UserDto signup(UserDto userDto) {
        if (!verifyCode(userDto.getEmail(), userDto.getVerificationCode())) {
            throw new IllegalArgumentException("Invalid verification code");
        }
        // Use the User constructor instead of setters
        User user = new User(
                userDto.getEmail(),
                passwordEncoder.encode(userDto.getPassword()),
                "USER"
        );
        User savedUser = userRepository.save(user);
        logger.info("User signed up: {}", savedUser.getEmail());
        return new UserDto(savedUser.getId(), savedUser.getEmail(), null, savedUser.getRole(), savedUser.getCreatedAt());
    }

    // 기존 login, loginWithOAuth2 유지
}