package com.example.tourism_service.repository;

import com.example.tourism_service.entity.License;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface LicenseRepository extends JpaRepository<License, UUID> {
    Optional<License> findByCode(String code);
}