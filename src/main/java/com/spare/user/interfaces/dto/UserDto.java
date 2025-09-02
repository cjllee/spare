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

    public User toEntity() {
        return new User(email, password, role);
    }
}