package com.spare.user.interfaces.dto;

import com.spare.user.domain.User;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "사용자 정보")
public class UserDto {

    @Schema(description = "사용자 ID", example = "1")
    private Long id;

    @Schema(description = "이메일", example = "user@example.com")
    private String email;

    @Schema(description = "비밀번호", example = "password123")
    private String password;

    @Schema(description = "권한", example = "USER")
    private String role;

    @Schema(description = "생성일시")
    private LocalDateTime createdAt;

    @Schema(description = "인증 코드", example = "123456")
    private String verificationCode;

    // 새로운 생성자 추가
    public UserDto(Long id, String email, String password, String role, LocalDateTime createdAt) {
        this.id = id;
        this.email = email;
        this.password = password;
        this.role = role;
        this.createdAt = createdAt;
        this.verificationCode = null;
    }

    public User toEntity() {
        return new User(email, password, role);
    }
}
