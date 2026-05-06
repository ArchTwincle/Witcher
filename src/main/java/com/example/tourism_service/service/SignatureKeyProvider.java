package com.example.tourism_service.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Objects;

@Service
public class SignatureKeyProvider {

    private final ResourceLoader resourceLoader;

    @Value("${signature.key-store}")
    private String keyStorePath;

    @Value("${signature.key-store-password}")
    private String keyStorePassword;

    @Value("${signature.key-password:}")
    private String keyPassword;

    @Value("${signature.key-alias}")
    private String keyAlias;

    @Value("${signature.key-store-type:PKCS12}")
    private String keyStoreType;

    private volatile PrivateKey privateKey;
    private volatile X509Certificate certificate;
    private volatile PublicKey publicKey;

    public SignatureKeyProvider(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    public void init() {
        loadKeys();
    }

    public PrivateKey getPrivateKey() {
        ensureLoaded();
        return privateKey;
    }

    public PublicKey getPublicKey() {
        ensureLoaded();
        return publicKey;
    }

    public X509Certificate getCertificate() {
        ensureLoaded();
        return certificate;
    }

    public String getPublicKeyBase64() {
        ensureLoaded();
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    private void ensureLoaded() {
        if (privateKey != null && certificate != null && publicKey != null) {
            return;
        }

        synchronized (this) {
            if (privateKey == null || certificate == null || publicKey == null) {
                loadKeys();
            }
        }
    }

    private void loadKeys() {
        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);

            try (InputStream inputStream = openKeyStoreStream()) {
                keyStore.load(inputStream, keyStorePassword.toCharArray());
            }

            String effectiveKeyPassword = keyPassword == null || keyPassword.isBlank()
                    ? keyStorePassword
                    : keyPassword;

            Key key = keyStore.getKey(keyAlias, effectiveKeyPassword.toCharArray());

            if (!(key instanceof PrivateKey loadedPrivateKey)) {
                throw new IllegalStateException("Ключ с alias '" + keyAlias + "' не является приватным ключом");
            }

            Certificate loadedCertificate = keyStore.getCertificate(keyAlias);

            if (loadedCertificate == null) {
                throw new IllegalStateException("Сертификат с alias '" + keyAlias + "' не найден в keystore");
            }

            if (!(loadedCertificate instanceof X509Certificate x509Certificate)) {
                throw new IllegalStateException("Сертификат с alias '" + keyAlias + "' не является X509Certificate");
            }

            this.privateKey = loadedPrivateKey;
            this.certificate = x509Certificate;
            this.publicKey = x509Certificate.getPublicKey();
        } catch (Exception e) {
            throw new IllegalStateException("Не удалось загрузить keystore/ключи для ЭЦП: " + e.getMessage(), e);
        }
    }

    private InputStream openKeyStoreStream() throws Exception {
        Resource resource = resolveResource(keyStorePath);

        if (!resource.exists()) {
            throw new IllegalStateException("Keystore не найден по пути: " + keyStorePath);
        }

        return resource.getInputStream();
    }

    private Resource resolveResource(String path) {
        Objects.requireNonNull(path, "Путь к keystore не должен быть null");

        if (path.startsWith("classpath:") || path.startsWith("file:")) {
            return resourceLoader.getResource(path);
        }

        Resource classpathResource = resourceLoader.getResource("classpath:" + path);

        if (classpathResource.exists()) {
            return classpathResource;
        }

        return resourceLoader.getResource("file:" + path);
    }
}