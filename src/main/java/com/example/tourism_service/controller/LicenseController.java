package com.example.tourism_service.controller;

import com.example.tourism_service.dto.ActivateLicenseRequest;
import com.example.tourism_service.dto.CheckLicenseRequest;
import com.example.tourism_service.dto.CreateLicenseRequest;
import com.example.tourism_service.dto.RenewLicenseRequest;
import com.example.tourism_service.dto.TicketResponse;
import com.example.tourism_service.entity.License;
import com.example.tourism_service.entity.User;
import com.example.tourism_service.repository.UserRepository;
import com.example.tourism_service.service.LicenseService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/licenses")
public class LicenseController {

    private final LicenseService licenseService;
    private final UserRepository userRepository;

    public LicenseController(LicenseService licenseService,
                             UserRepository userRepository) {
        this.licenseService = licenseService;
        this.userRepository = userRepository;
    }

    @PostMapping("/create")
    public ResponseEntity<License> createLicense(@RequestBody CreateLicenseRequest request,
                                                 Authentication authentication) {
        Long adminId = getCurrentUserId(authentication);
        License license = licenseService.createLicense(request, adminId);
        return ResponseEntity.status(HttpStatus.CREATED).body(license);
    }

    @PostMapping("/activate")
    public ResponseEntity<TicketResponse> activateLicense(@RequestBody ActivateLicenseRequest request,
                                                          Authentication authentication) {
        Long userId = getCurrentUserId(authentication);
        TicketResponse response = licenseService.activateLicense(request, userId);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/check")
    public ResponseEntity<TicketResponse> checkLicense(@RequestBody CheckLicenseRequest request,
                                                       Authentication authentication) {
        Long userId = getCurrentUserId(authentication);
        TicketResponse response = licenseService.checkLicense(request, userId);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/renew")
    public ResponseEntity<TicketResponse> renewLicense(@RequestBody RenewLicenseRequest request,
                                                       Authentication authentication) {
        Long userId = getCurrentUserId(authentication);
        TicketResponse response = licenseService.renewLicense(request, userId);
        return ResponseEntity.ok(response);
    }

    private Long getCurrentUserId(Authentication authentication) {
        if (authentication == null || authentication.getName() == null) {
            throw new RuntimeException("Пользователь не авторизован");
        }

        String username = authentication.getName();

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Пользователь из JWT не найден"));

        return user.getId();
    }
}