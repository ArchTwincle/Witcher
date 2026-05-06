package com.example.tourism_service.dto;

import java.time.LocalDate;
import java.time.LocalDateTime;

public class Ticket {

    private LocalDateTime serverDate;
    private Long ticketLifetimeSeconds;
    private LocalDate activationDate;
    private LocalDate expirationDate;
    private Long userId;
    private String deviceId;
    private Boolean blocked;

    public Ticket() {
    }

    public Ticket(LocalDateTime serverDate,
                  Long ticketLifetimeSeconds,
                  LocalDate activationDate,
                  LocalDate expirationDate,
                  Long userId,
                  String deviceId,
                  Boolean blocked) {
        this.serverDate = serverDate;
        this.ticketLifetimeSeconds = ticketLifetimeSeconds;
        this.activationDate = activationDate;
        this.expirationDate = expirationDate;
        this.userId = userId;
        this.deviceId = deviceId;
        this.blocked = blocked;
    }

    public LocalDateTime getServerDate() {
        return serverDate;
    }

    public void setServerDate(LocalDateTime serverDate) {
        this.serverDate = serverDate;
    }

    public Long getTicketLifetimeSeconds() {
        return ticketLifetimeSeconds;
    }

    public void setTicketLifetimeSeconds(Long ticketLifetimeSeconds) {
        this.ticketLifetimeSeconds = ticketLifetimeSeconds;
    }

    public LocalDate getActivationDate() {
        return activationDate;
    }

    public void setActivationDate(LocalDate activationDate) {
        this.activationDate = activationDate;
    }

    public LocalDate getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(LocalDate expirationDate) {
        this.expirationDate = expirationDate;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    public Boolean getBlocked() {
        return blocked;
    }

    public void setBlocked(Boolean blocked) {
        this.blocked = blocked;
    }
}