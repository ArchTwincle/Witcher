package com.example.tourism_service.dto;

public class JwtResponse {
    private String accessToken;
    private String refreshToken;

    // Конструктор по умолчанию (вместо @NoArgsConstructor)
    public JwtResponse() {
    }

    // Конструктор со всеми аргументами (вместо @AllArgsConstructor)
    public JwtResponse(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    // Геттеры и сеттеры (вместо @Data)
    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}