package com.example.tourism_service.service;

import com.example.tourism_service.dto.Ticket;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Signature;
import java.util.Base64;

@Service
public class SignatureService {

    private final SignatureKeyProvider signatureKeyProvider;
    private final CanonicalizationService canonicalizationService;

    @Value("${signature.algorithm:SHA256withRSA}")
    private String algorithm;

    public SignatureService(SignatureKeyProvider signatureKeyProvider,
                            CanonicalizationService canonicalizationService) {
        this.signatureKeyProvider = signatureKeyProvider;
        this.canonicalizationService = canonicalizationService;
    }

    public String signTicket(Ticket ticket) {
        try {
            byte[] payload = canonicalizationService.canonicalize(ticket);

            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(signatureKeyProvider.getPrivateKey());
            signature.update(payload);

            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception e) {
            throw new RuntimeException("Ошибка при формировании ЭЦП для Ticket", e);
        }
    }

    public boolean verifyTicket(Ticket ticket, String signatureBase64) {
        try {
            byte[] payload = canonicalizationService.canonicalize(ticket);
            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);

            Signature signature = Signature.getInstance(algorithm);
            signature.initVerify(signatureKeyProvider.getPublicKey());
            signature.update(payload);

            return signature.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }

    public boolean verify(Ticket ticket, String signatureBase64) {
        return verifyTicket(ticket, signatureBase64);
    }
}