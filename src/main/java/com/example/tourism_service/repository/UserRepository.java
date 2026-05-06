package com.example.tourism_service.repository;

import com.example.tourism_service.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    // Метод для поиска пользователя по логину
    Optional<User> findByUsername(String username);
}