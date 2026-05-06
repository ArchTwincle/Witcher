package com.example.tourism_service.service;

import com.example.tourism_service.dto.JwtResponse;
import com.example.tourism_service.entity.SessionStatus;
import com.example.tourism_service.entity.UserSession;
import com.example.tourism_service.repository.UserSessionRepository;
import com.example.tourism_service.security.JwtTokenProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
public class AuthService {

    private final JwtTokenProvider tokenProvider;
    private final UserSessionRepository sessionRepository;

    public AuthService(JwtTokenProvider tokenProvider, UserSessionRepository sessionRepository) {
        this.tokenProvider = tokenProvider;
        this.sessionRepository = sessionRepository;
    }

    @Transactional
    public JwtResponse login(String username) {
        String accessToken = tokenProvider.generateAccessToken(username);
        String refreshToken = tokenProvider.generateRefreshToken(username);

        // Заменяем Builder на обычный объект и сеттеры
        UserSession session = new UserSession();
        session.setUserEmail(username);
        session.setAccessToken(accessToken);
        session.setRefreshToken(refreshToken);
        session.setRefreshTokenExpiry(Instant.now().plus(7, ChronoUnit.DAYS));
        session.setStatus(SessionStatus.ACTIVE);

        sessionRepository.save(session);

        return new JwtResponse(accessToken, refreshToken);
    }

    @Transactional
    public JwtResponse refresh(String oldRefreshToken) {
        if (!tokenProvider.validateToken(oldRefreshToken)) {
            throw new RuntimeException("Refresh токен невалиден");
        }

        UserSession session = sessionRepository.findByRefreshToken(oldRefreshToken)
                .orElseThrow(() -> new RuntimeException("Сессия не найдена"));

        if (session.getStatus() != SessionStatus.ACTIVE) {
            session.setStatus(SessionStatus.REVOKED);
            sessionRepository.save(session);
            throw new RuntimeException("Нарушение безопасности!");
        }

        session.setStatus(SessionStatus.USED);
        sessionRepository.save(session);

        String username = tokenProvider.getUsernameFromToken(oldRefreshToken);
        return login(username);
    }
}