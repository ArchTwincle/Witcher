package com.example.tourism_service.controller;

import com.example.tourism_service.dto.JwtResponse;
import com.example.tourism_service.service.AuthService;
import com.example.tourism_service.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final UserService userService;
    private final AuthenticationManager authenticationManager;

    // Явный конструктор для внедрения зависимостей вместо @RequiredArgsConstructor
    public AuthController(AuthService authService,
                          UserService userService,
                          AuthenticationManager authenticationManager) {
        this.authService = authService;
        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }

    // Вход: проверяем пароль и выдаем пару токенов
    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");

        // Аутентификация через Spring Security
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

        // Если успешно — генерируем токены и создаем сессию в БД
        return ResponseEntity.ok(authService.login(username));
    }

    // Регистрация: только для АДМИНА
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody Map<String, String> request) {
        userService.register(request.get("username"), request.get("password"), request.get("role"));
        return ResponseEntity.ok("Пользователь создан");
    }

    // Обновление: замена старого Refresh-токена на новую пару
    @PostMapping("/refresh")
    public ResponseEntity<JwtResponse> refresh(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        return ResponseEntity.ok(authService.refresh(refreshToken));
    }
}