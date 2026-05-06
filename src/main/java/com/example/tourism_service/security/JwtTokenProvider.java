package com.example.tourism_service.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtTokenProvider {

    // Считываем секрет из application.properties
    @Value("${jwt.secret}")
    private String secret;

    // Считываем время жизни из application.properties (опционально, но лучше сделать так)
    @Value("${jwt.access-expiration}")
    private long accessExpiration;

    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;

    private Key key;

    // Этот метод выполнится ПОСЛЕ того, как Spring подставит значения из конфига
    @PostConstruct
    protected void init() {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String generateAccessToken(String username) {
        return generateToken(username, accessExpiration);
    }

    public String generateRefreshToken(String username) {
        return generateToken(username, refreshExpiration);
    }

    private String generateToken(String username, long expiry) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiry))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String getUsernameFromToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}