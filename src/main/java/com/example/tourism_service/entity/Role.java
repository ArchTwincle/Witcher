package com.example.tourism_service.entity;

import org.springframework.security.core.GrantedAuthority;

public enum Role implements GrantedAuthority {
    USER, GUIDE, ADMIN;

    @Override
    public String getAuthority() {
        return "ROLE_" + name();
    }
}