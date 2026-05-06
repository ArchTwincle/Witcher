package com.example.tourism_service.repository;

import com.example.tourism_service.entity.DeviceLicense;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface DeviceLicenseRepository extends JpaRepository<DeviceLicense, UUID> {
    long countByLicenseId(UUID licenseId);
    Optional<DeviceLicense> findByLicenseIdAndDeviceId(UUID licenseId, UUID deviceId);
    List<DeviceLicense> findByLicenseId(UUID licenseId);
}