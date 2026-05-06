package com.example.tourism_service.service;

import com.example.tourism_service.dto.ActivateLicenseRequest;
import com.example.tourism_service.dto.CheckLicenseRequest;
import com.example.tourism_service.dto.CreateLicenseRequest;
import com.example.tourism_service.dto.RenewLicenseRequest;
import com.example.tourism_service.dto.Ticket;
import com.example.tourism_service.dto.TicketResponse;
import com.example.tourism_service.entity.Device;
import com.example.tourism_service.entity.DeviceLicense;
import com.example.tourism_service.entity.License;
import com.example.tourism_service.entity.LicenseHistory;
import com.example.tourism_service.entity.LicenseType;
import com.example.tourism_service.entity.Product;
import com.example.tourism_service.entity.User;
import com.example.tourism_service.repository.DeviceLicenseRepository;
import com.example.tourism_service.repository.DeviceRepository;
import com.example.tourism_service.repository.LicenseHistoryRepository;
import com.example.tourism_service.repository.LicenseRepository;
import com.example.tourism_service.repository.LicenseTypeRepository;
import com.example.tourism_service.repository.ProductRepository;
import com.example.tourism_service.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
public class LicenseService {

    private final LicenseRepository licenseRepository;
    private final DeviceRepository deviceRepository;
    private final DeviceLicenseRepository deviceLicenseRepository;
    private final LicenseHistoryRepository licenseHistoryRepository;
    private final ProductRepository productRepository;
    private final LicenseTypeRepository licenseTypeRepository;
    private final UserRepository userRepository;
    private final SignatureService signatureService;

    public LicenseService(LicenseRepository licenseRepository,
                          DeviceRepository deviceRepository,
                          DeviceLicenseRepository deviceLicenseRepository,
                          LicenseHistoryRepository licenseHistoryRepository,
                          ProductRepository productRepository,
                          LicenseTypeRepository licenseTypeRepository,
                          UserRepository userRepository,
                          SignatureService signatureService) {
        this.licenseRepository = licenseRepository;
        this.deviceRepository = deviceRepository;
        this.deviceLicenseRepository = deviceLicenseRepository;
        this.licenseHistoryRepository = licenseHistoryRepository;
        this.productRepository = productRepository;
        this.licenseTypeRepository = licenseTypeRepository;
        this.userRepository = userRepository;
        this.signatureService = signatureService;
    }

    @Transactional
    public License createLicense(CreateLicenseRequest request, Long adminId) {
        User admin = userRepository.findById(adminId)
                .orElseThrow(() -> new RuntimeException("Администратор не найден"));

        User owner = userRepository.findById(request.getOwnerId())
                .orElseThrow(() -> new RuntimeException("Владелец лицензии не найден"));

        Product product = productRepository.findById(UUID.fromString(request.getProductId()))
                .orElseThrow(() -> new RuntimeException("Продукт не найден"));

        if (Boolean.TRUE.equals(product.getIsBlocked())) {
            throw new RuntimeException("Нельзя создать лицензию для заблокированного продукта");
        }

        LicenseType licenseType = licenseTypeRepository.findById(UUID.fromString(request.getLicenseTypeId()))
                .orElseThrow(() -> new RuntimeException("Тип лицензии не найден"));

        License license = new License();
        license.setCode(generateLicenseCode());
        license.setOwner(owner);
        license.setUser(null);
        license.setProduct(product);
        license.setType(licenseType);
        license.setFirstActivationDate(null);
        license.setEndingDate(null);
        license.setBlocked(false);
        license.setDeviceCount(request.getDeviceCount() != null ? request.getDeviceCount() : 3);
        license.setDescription(request.getDescription());

        License savedLicense = licenseRepository.save(license);

        LicenseHistory history = new LicenseHistory();
        history.setLicense(savedLicense);
        history.setUser(admin);
        history.setStatus("CREATED");
        history.setChangeDate(LocalDate.now());
        history.setDescription("Лицензия создана администратором");
        licenseHistoryRepository.save(history);

        return savedLicense;
    }

    @Transactional
    public TicketResponse activateLicense(ActivateLicenseRequest request, Long userId) {
        User currentUser = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Пользователь не найден"));

        License license = licenseRepository.findByCode(request.getLicenseCode())
                .orElseThrow(() -> new RuntimeException("Лицензия не найдена"));

        validateLicenseForUse(license);

        if (license.getUser() != null && !license.getUser().getId().equals(userId)) {
            throw new RuntimeException("Лицензия уже активирована другим пользователем");
        }

        Device device = deviceRepository.findByMacAddress(request.getMacAddress())
                .orElseGet(() -> {
                    Device newDevice = new Device();
                    newDevice.setMacAddress(request.getMacAddress());
                    newDevice.setName(request.getDeviceName());
                    newDevice.setUser(currentUser);
                    return deviceRepository.save(newDevice);
                });

        if (device.getUser() != null && !device.getUser().getId().equals(userId)) {
            throw new RuntimeException("Устройство принадлежит другому пользователю");
        }

        boolean alreadyActivated = deviceLicenseRepository
                .findByLicenseIdAndDeviceId(license.getId(), device.getId())
                .isPresent();

        if (!alreadyActivated) {
            long currentDeviceCount = deviceLicenseRepository.countByLicenseId(license.getId());
            int deviceLimit = license.getDeviceCount() != null ? license.getDeviceCount() : 1;

            if (currentDeviceCount >= deviceLimit) {
                throw new RuntimeException("Превышен лимит устройств для лицензии");
            }

            DeviceLicense deviceLicense = new DeviceLicense();
            deviceLicense.setLicense(license);
            deviceLicense.setDevice(device);
            deviceLicense.setActivationDate(LocalDate.now());
            deviceLicenseRepository.save(deviceLicense);
        }

        if (license.getFirstActivationDate() == null) {
            license.setUser(currentUser);
            license.setFirstActivationDate(LocalDate.now());

            if (license.getType() != null && license.getType().getDefaultDurationInDays() != null) {
                license.setEndingDate(
                        LocalDate.now().plusDays(
                                license.getType().getDefaultDurationInDays()
                        )
                );
            }

            licenseRepository.save(license);
        }

        LicenseHistory history = new LicenseHistory();
        history.setLicense(license);
        history.setUser(currentUser);
        history.setChangeDate(LocalDate.now());

        if (alreadyActivated) {
            history.setStatus("REACTIVATED");
            history.setDescription("Повторная активация лицензии на устройстве: " + request.getMacAddress());
        } else {
            history.setStatus("ACTIVATED");
            history.setDescription("Лицензия активирована на устройстве: " + request.getMacAddress());
        }

        licenseHistoryRepository.save(history);

        return buildTicketResponse(license, device);
    }

    @Transactional(readOnly = true)
    public TicketResponse checkLicense(CheckLicenseRequest request, Long userId) {
        License license = licenseRepository.findByCode(request.getLicenseCode())
                .orElseThrow(() -> new RuntimeException("Лицензия не найдена"));

        validateLicenseForUse(license);

        if (license.getUser() == null || !license.getUser().getId().equals(userId)) {
            throw new RuntimeException("Лицензия не принадлежит текущему пользователю");
        }

        if (request.getProductId() != null && !request.getProductId().isBlank()) {
            UUID requestedProductId = UUID.fromString(request.getProductId());

            if (license.getProduct() == null || !license.getProduct().getId().equals(requestedProductId)) {
                throw new RuntimeException("Лицензия не относится к указанному продукту");
            }
        }

        Device device = deviceRepository.findByMacAddress(request.getMacAddress())
                .orElseThrow(() -> new RuntimeException("Устройство не найдено"));

        if (device.getUser() != null && !device.getUser().getId().equals(userId)) {
            throw new RuntimeException("Устройство принадлежит другому пользователю");
        }

        deviceLicenseRepository.findByLicenseIdAndDeviceId(license.getId(), device.getId())
                .orElseThrow(() -> new RuntimeException("Лицензия не активирована на этом устройстве"));

        return buildTicketResponse(license, device);
    }

    @Transactional
    public TicketResponse renewLicense(RenewLicenseRequest request, Long userId) {
        User currentUser = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Пользователь не найден"));

        License license = licenseRepository.findByCode(request.getLicenseCode())
                .orElseThrow(() -> new RuntimeException("Лицензия не найдена"));

        if (Boolean.TRUE.equals(license.getBlocked())) {
            throw new RuntimeException("Лицензия заблокирована");
        }

        if (license.getProduct() != null && Boolean.TRUE.equals(license.getProduct().getIsBlocked())) {
            throw new RuntimeException("Продукт заблокирован");
        }

        if (license.getFirstActivationDate() == null || license.getUser() == null) {
            throw new RuntimeException("Нельзя продлить неактивированную лицензию");
        }

        if (!license.getUser().getId().equals(userId)) {
            throw new RuntimeException("Лицензия не принадлежит текущему пользователю");
        }

        if (license.getEndingDate() != null &&
                license.getEndingDate().isAfter(LocalDate.now().plusDays(7))) {
            throw new RuntimeException("Лицензию можно продлить только если она истекла или истекает в течение 7 дней");
        }

        Device device = deviceRepository.findByMacAddress(request.getMacAddress())
                .orElseThrow(() -> new RuntimeException("Устройство не найдено"));

        if (device.getUser() != null && !device.getUser().getId().equals(userId)) {
            throw new RuntimeException("Устройство принадлежит другому пользователю");
        }

        deviceLicenseRepository.findByLicenseIdAndDeviceId(license.getId(), device.getId())
                .orElseThrow(() -> new RuntimeException("Лицензия не активирована на этом устройстве"));

        int extraDays = resolveRenewDays(request, license);

        LocalDate baseDate = license.getEndingDate() != null && license.getEndingDate().isAfter(LocalDate.now())
                ? license.getEndingDate()
                : LocalDate.now();

        license.setEndingDate(baseDate.plusDays(extraDays));
        License savedLicense = licenseRepository.save(license);

        LicenseHistory history = new LicenseHistory();
        history.setLicense(savedLicense);
        history.setUser(currentUser);
        history.setStatus("RENEWED");
        history.setChangeDate(LocalDate.now());
        history.setDescription(
                request.getDescription() != null ? request.getDescription() : "Лицензия продлена"
        );
        licenseHistoryRepository.save(history);

        return buildTicketResponse(savedLicense, device);
    }

    private void validateLicenseForUse(License license) {
        if (Boolean.TRUE.equals(license.getBlocked())) {
            throw new RuntimeException("Лицензия заблокирована");
        }

        if (license.getEndingDate() != null && license.getEndingDate().isBefore(LocalDate.now())) {
            throw new RuntimeException("Срок действия лицензии истек");
        }

        if (license.getProduct() != null && Boolean.TRUE.equals(license.getProduct().getIsBlocked())) {
            throw new RuntimeException("Продукт заблокирован");
        }
    }

    private int resolveRenewDays(RenewLicenseRequest request, License license) {
        if (request.getExtraDays() != null && request.getExtraDays() > 0) {
            return request.getExtraDays();
        }

        if (license.getType() != null && license.getType().getDefaultDurationInDays() != null) {
            return license.getType().getDefaultDurationInDays();
        }

        throw new RuntimeException("Не указано количество дней для продления");
    }

    private TicketResponse buildTicketResponse(License license, Device device) {
        LocalDateTime now = LocalDateTime.now();

        long ttlSeconds = 0;
        if (license.getEndingDate() != null) {
            LocalDateTime expirationDateTime = license.getEndingDate().plusDays(1).atStartOfDay();
            ttlSeconds = Math.max(0, ChronoUnit.SECONDS.between(now, expirationDateTime));
        }

        Long ticketUserId = license.getUser() != null
                ? license.getUser().getId()
                : license.getOwner().getId();

        Ticket ticket = new Ticket();
        ticket.setServerDate(now);
        ticket.setTicketLifetimeSeconds(ttlSeconds);
        ticket.setActivationDate(license.getFirstActivationDate());
        ticket.setExpirationDate(license.getEndingDate());
        ticket.setUserId(ticketUserId);
        ticket.setDeviceId(device.getMacAddress());
        ticket.setBlocked(license.getBlocked());

        String signature = signatureService.signTicket(ticket);

        return new TicketResponse(ticket, signature);
    }

    private String generateLicenseCode() {
        return UUID.randomUUID().toString().replace("-", "").toUpperCase();
    }
}