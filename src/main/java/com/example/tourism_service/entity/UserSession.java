package com.example.tourism_service.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_sessions")
public class UserSession {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    private String userEmail;

    @Column(length = 1024)
    private String accessToken;

    @Column(length = 1024)
    private String refreshToken;

    private Instant refreshTokenExpiry;

    @Enumerated(EnumType.STRING)
    private SessionStatus status;

    // 1. Конструктор без аргументов (вместо @NoArgsConstructor)
    public UserSession() {
    }

    // 2. Конструктор со всеми аргументами (вместо @AllArgsConstructor)
    public UserSession(UUID id, String userEmail, String accessToken, String refreshToken, Instant refreshTokenExpiry, SessionStatus status) {
        this.id = id;
        this.userEmail = userEmail;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.refreshTokenExpiry = refreshTokenExpiry;
        this.status = status;
    }

    // 3. Геттеры и Сеттеры (вместо @Getter и @Setter)
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getUserEmail() { return userEmail; }
    public void setUserEmail(String userEmail) { this.userEmail = userEmail; }

    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }

    public String getRefreshToken() { return refreshToken; }
    public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }

    public Instant getRefreshTokenExpiry() { return refreshTokenExpiry; }
    public void setRefreshTokenExpiry(Instant refreshTokenExpiry) { this.refreshTokenExpiry = refreshTokenExpiry; }

    public SessionStatus getStatus() { return status; }
    public void setStatus(SessionStatus status) { this.status = status; }
}