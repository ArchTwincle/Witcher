package com.example.tourism_service.repository;

import com.example.tourism_service.entity.Device;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface DeviceRepository extends JpaRepository<Device, UUID> {
    Optional<Device> findByMacAddress(String macAddress);
}