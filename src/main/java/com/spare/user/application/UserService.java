package com.spare.user.application;

import org.springframework.security.oauth2.core.user.OAuth2User;
import com.spare.common.security.JwtUtil;
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
    private final JwtUtil jwtUtil;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, EmailUtil emailUtil, RedisTemplate<String, Object> redisTemplate, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailUtil = emailUtil;
        this.redisTemplate = redisTemplate;
        this.jwtUtil = jwtUtil;
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

    public String login(UserDto userDto) {
        User user = userRepository.findByEmail(userDto.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        if (!passwordEncoder.matches(userDto.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Invalid password");
        }
        logger.info("User logged in: {}", user.getEmail());
        return jwtUtil.generateToken(user.getEmail(), user.getRole());
    }


    public String loginWithOAuth2(OAuth2User oAuth2User) {
        // OAuth2User에서 이메일 정보 추출
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        if (email == null) {
            logger.error("Email not found in OAuth2 user attributes");
            throw new IllegalArgumentException("Email not found in OAuth2 user attributes");
        }

        // 기존 사용자인지 확인
        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            // OAuth2 사용자임을 나타내는 특별한 패스워드 설정
            // 실제로는 이 패스워드로 로그인할 수 없으며, OAuth2로만 로그인 가능
            String oauthPassword = passwordEncoder.encode("OAUTH2_PROVIDER_" + System.currentTimeMillis());

            user = new User(
                    email,
                    oauthPassword, // OAuth2 전용 패스워드 (실제 사용 불가)
                    "USER"
            );
            user = userRepository.save(user);
            logger.info("New OAuth2 user created: {} (provider: {})", email, oAuth2User.getAttribute("iss"));
        } else {
            logger.info("Existing OAuth2 user logged in: {}", email);
        }

        // JWT 토큰 생성 및 반환
        String token = jwtUtil.generateToken(user.getEmail(), user.getRole());
        logger.info("OAuth2 login successful for user: {}", email);

        return token;
    }

}