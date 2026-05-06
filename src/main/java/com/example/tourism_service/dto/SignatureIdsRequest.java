package com.example.tourism_service.dto;

import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import java.util.UUID;

public class SignatureIdsRequest {

    @NotEmpty(message = "ids must not be empty")
    private List<UUID> ids;

    public SignatureIdsRequest() {
    }

    public List<UUID> getIds() {
        return ids;
    }

    public void setIds(List<UUID> ids) {
        this.ids = ids;
    }
}