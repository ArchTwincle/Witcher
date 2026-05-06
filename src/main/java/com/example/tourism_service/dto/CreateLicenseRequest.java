package com.example.tourism_service.dto;

public class CreateLicenseRequest {

    private String productId;
    private String licenseTypeId;
    private Long ownerId;
    private String description;
    private Integer deviceCount;

    public CreateLicenseRequest() {
    }

    public String getProductId() {
        return productId;
    }

    public void setProductId(String productId) {
        this.productId = productId;
    }

    public String getLicenseTypeId() {
        return licenseTypeId;
    }

    public void setLicenseTypeId(String licenseTypeId) {
        this.licenseTypeId = licenseTypeId;
    }

    public Long getOwnerId() {
        return ownerId;
    }

    public void setOwnerId(Long ownerId) {
        this.ownerId = ownerId;
    }

    public String getDescription() {
        return description;
    }

    public Integer getDeviceCount() {
        return deviceCount;
    }

    public void setDeviceCount(Integer deviceCount) {
        this.deviceCount = deviceCount;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}