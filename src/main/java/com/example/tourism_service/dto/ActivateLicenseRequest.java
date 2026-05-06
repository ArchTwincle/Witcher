package com.example.tourism_service.dto;

public class ActivateLicenseRequest {

    private String licenseCode;
    private String activationKey;
    private String macAddress;
    private String deviceMac;
    private String deviceName;

    public String getLicenseCode() {
        if (licenseCode != null && !licenseCode.isBlank()) {
            return licenseCode;
        }

        return activationKey;
    }

    public void setLicenseCode(String licenseCode) {
        this.licenseCode = licenseCode;
    }

    public String getActivationKey() {
        if (activationKey != null && !activationKey.isBlank()) {
            return activationKey;
        }

        return licenseCode;
    }

    public void setActivationKey(String activationKey) {
        this.activationKey = activationKey;
    }

    public String getMacAddress() {
        if (macAddress != null && !macAddress.isBlank()) {
            return macAddress;
        }

        return deviceMac;
    }

    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    public String getDeviceMac() {
        if (deviceMac != null && !deviceMac.isBlank()) {
            return deviceMac;
        }

        return macAddress;
    }

    public void setDeviceMac(String deviceMac) {
        this.deviceMac = deviceMac;
    }

    public String getDeviceName() {
        return deviceName;
    }

    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }
}