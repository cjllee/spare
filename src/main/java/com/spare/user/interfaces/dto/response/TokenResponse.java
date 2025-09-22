package com.spare.user.interfaces.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "토큰 응답")
public class TokenResponse {

    @Schema(description = "액세스 토큰", example = "eyJhbGciOiJIUzUxMiJ9...")
    private String accessToken;

    @Schema(description = "리프레시 토큰", example = "eyJhbGciOiJIUzUxMiJ9...")
    private String refreshToken;

    @Schema(description = "토큰 타입", example = "Bearer")
    private String tokenType = "Bearer";

    @Schema(description = "액세스 토큰 만료 시간(초)", example = "1800")
    private Long accessTokenExpiresIn = 1800L; // 30분

    public TokenResponse(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.tokenType = "Bearer";
        this.accessTokenExpiresIn = 1800L;
    }
}