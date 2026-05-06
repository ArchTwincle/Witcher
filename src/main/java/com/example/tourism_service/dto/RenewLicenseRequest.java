package com.example.tourism_service.dto;

public class RenewLicenseRequest {

    private String licenseCode;
    private String macAddress;
    private Integer extraDays;
    private String description;

    public RenewLicenseRequest() {
    }

    public String getLicenseCode() {
        return licenseCode;
    }

    public void setLicenseCode(String licenseCode) {
        this.licenseCode = licenseCode;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    public Integer getExtraDays() {
        return extraDays;
    }

    public void setExtraDays(Integer extraDays) {
        this.extraDays = extraDays;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}