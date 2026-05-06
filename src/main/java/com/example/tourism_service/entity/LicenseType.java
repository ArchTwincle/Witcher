package com.example.tourism_service.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import java.util.UUID;

@Entity
@Table(name = "license_type")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class LicenseType {


    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String name;

    @Column(name = "default_duration_in_days", nullable = false)
    private Integer defaultDurationInDays;

    @Column(columnDefinition = "TEXT")
    private String description;

    public LicenseType() {
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Integer getDefaultDurationInDays() {
        return defaultDurationInDays;
    }

    public void setDefaultDurationInDays(Integer defaultDurationInDays) {
        this.defaultDurationInDays = defaultDurationInDays;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}