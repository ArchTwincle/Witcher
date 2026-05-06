package com.example.tourism_service.entity;

public enum SessionStatus {
    ACTIVE,  // Сессия активна
    USED,    // Refresh-токен уже был использован для обновления
    REVOKED  // Сессия отозвана (например, при попытке взлома)
}