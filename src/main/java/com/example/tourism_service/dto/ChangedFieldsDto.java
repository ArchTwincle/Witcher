package com.example.tourism_service.dto;

import java.util.List;

public class ChangedFieldsDto {

    private List<String> changed;

    public ChangedFieldsDto() {
    }

    public ChangedFieldsDto(List<String> changed) {
        this.changed = changed;
    }

    public List<String> getChanged() {
        return changed;
    }

    public void setChanged(List<String> changed) {
        this.changed = changed;
    }
}