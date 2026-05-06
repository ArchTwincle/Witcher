package com.example.tourism_service.repository;

import com.example.tourism_service.entity.LicenseHistory;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface LicenseHistoryRepository extends JpaRepository<LicenseHistory, UUID> {
    List<LicenseHistory> findByLicenseIdOrderByChangeDateDesc(UUID licenseId);
}