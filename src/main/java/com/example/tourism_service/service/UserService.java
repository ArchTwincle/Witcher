package com.example.tourism_service.service;

import com.example.tourism_service.entity.Role;
import com.example.tourism_service.entity.User;
import com.example.tourism_service.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Set;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public void register(String username, String password, String roleName) {
        if (password.length() < 8 || !password.matches(".*\\d.*") || !password.matches(".*[!@#$%^&*()].*")) {
            throw new RuntimeException("Пароль слишком слабый!");
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));

        try {
            Role role = Role.valueOf(roleName.toUpperCase());
            user.setRoles(Set.of(role));
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Роль " + roleName + " не существует!");
        }

        userRepository.save(user);
    }
}