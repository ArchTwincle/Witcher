package com.example.tourism_service.repository;

import com.example.tourism_service.entity.LicenseType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface LicenseTypeRepository extends JpaRepository<LicenseType, UUID> {
}