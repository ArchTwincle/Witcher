package com.example.tourism_service.repository;

import com.example.tourism_service.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, UUID> {

    // Для процесса Refresh: поиск сессии по рефреш-токену
    Optional<UserSession> findByRefreshToken(String refreshToken);

    // Для фильтра безопасности: поиск сессии по активному аксесс-токену
    Optional<UserSession> findByAccessToken(String accessToken);
}