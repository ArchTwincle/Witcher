package com.example.tourism_service.service;

import com.example.tourism_service.entity.MalwareSignature;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

@Component
public class SignaturePayloadBuilder {

    public byte[] buildPayload(MalwareSignature signature) {
        String payload = String.join("|",
                safe(signature.getThreatName()),
                normalizeHex(signature.getFirstBytesHex()),
                normalizeHex(signature.getRemainderHashHex()),
                String.valueOf(signature.getRemainderLength()),
                safe(signature.getFileType()),
                String.valueOf(signature.getOffsetStart()),
                String.valueOf(signature.getOffsetEnd()),
                signature.getStatus().name()
        );

        return payload.getBytes(StandardCharsets.UTF_8);
    }

    private String safe(String value) {
        return value == null ? "" : value.trim();
    }

    private String normalizeHex(String value) {
        return value == null ? "" : value.trim().toUpperCase();
    }
}