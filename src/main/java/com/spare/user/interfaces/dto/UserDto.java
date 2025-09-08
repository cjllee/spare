package com.spare.user.interfaces.dto;

import com.spare.user.domain.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserDto {
    private Long id;
    private String email;
    private String password;
    private String role;
    private LocalDateTime createdAt;
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