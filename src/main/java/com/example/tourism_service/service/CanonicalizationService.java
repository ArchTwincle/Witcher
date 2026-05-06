package com.example.tourism_service.service;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Service
public class CanonicalizationService {

    private static final BigInteger MIN_SAFE_INTEGER = BigInteger.valueOf(-9_007_199_254_740_991L);
    private static final BigInteger MAX_SAFE_INTEGER = BigInteger.valueOf(9_007_199_254_740_991L);

    private final ObjectMapper objectMapper;

    public CanonicalizationService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public byte[] canonicalize(Object payload) {
        String canonicalJson = canonicalizeToString(payload);
        return canonicalJson.getBytes(StandardCharsets.UTF_8);
    }

    public String canonicalizeToString(Object payload) {
        JsonNode node = toJsonNode(payload);

        StringBuilder canonicalJson = new StringBuilder();
        writeCanonicalJson(node, canonicalJson);

        return canonicalJson.toString();
    }

    private JsonNode toJsonNode(Object payload) {
        try {
            if (payload == null) {

                return objectMapper.nullNode();
            }

            if (payload instanceof String json) {
                return objectMapper.reader()
                        .with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                        .readTree(json);
            }

            return objectMapper.valueToTree(payload);
        } catch (Exception e) {

            throw new IllegalStateException("Ошибка преобразования payload в JSON для канонизации", e);
        }
    }

    private void writeCanonicalJson(JsonNode node, StringBuilder out) {
        if (node == null || node.isNull()) {
            out.append("null");
            return;
        }

        if (node.isObject()) {
            writeCanonicalObject((ObjectNode) node, out);
            return;
        }

        if (node.isArray()) {
            writeCanonicalArray(node, out);
            return;
        }

        if (node.isTextual()) {
            writeCanonicalString(node.textValue(), out);
            return;
        }

        if (node.isBoolean()) {
            out.append(node.booleanValue() ? "true" : "false");
            return;
        }

        if (node.isNumber()) {
            out.append(writeCanonicalNumber(node));
            return;
        }

        throw new IllegalStateException("Неподдерживаемый тип JSON-узла: " + node.getNodeType());
    }
    private void writeCanonicalObject(ObjectNode node, StringBuilder out) {
        List<String> fields = new ArrayList<>();

        node.fieldNames().forEachRemaining(fields::add);
        fields.sort(String::compareTo);

        out.append('{');

        for (int i = 0; i < fields.size(); i++) {
            if (i > 0) {
                out.append(',');
            }

            String fieldName = fields.get(i);

            writeCanonicalString(fieldName, out);
            out.append(':');
            writeCanonicalJson(node.get(fieldName), out);
        }

        out.append('}');
    }

    private void writeCanonicalArray(JsonNode node, StringBuilder out) {
        out.append('[');

        for (int i = 0; i < node.size(); i++) {
            if (i > 0) {
                out.append(',');
            }

            writeCanonicalJson(node.get(i), out);
        }

        out.append(']');
    }

    private void writeCanonicalString(String value, StringBuilder out) {
        if (value == null) {
            out.append("null");
            return;
        }

        validateNoLoneSurrogates(value);

        out.append('"');

        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);

            switch (character) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (character <= 0x1F) {
                        out.append("\\u");

                        String hex = Integer.toHexString(character);
                        out.append("0".repeat(4 - hex.length()));
                        out.append(hex);
                    } else {
                        out.append(character);
                    }
                }
            }
        }

        out.append('"');
    }

    private void validateNoLoneSurrogates(String value) {
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);

            if (Character.isHighSurrogate(character)) {
                if (i + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(i + 1))) {
                    throw new IllegalStateException("Одиночный high surrogate недопустим при канонизации");
                }

                i++;
                continue;
            }

            if (Character.isLowSurrogate(character)) {
                throw new IllegalStateException("Одиночный low surrogate недопустим при канонизации");
            }
        }
    }

    private String writeCanonicalNumber(JsonNode node) {
        validateIJsonNumber(node);

        double value = node.doubleValue();

        if (!Double.isFinite(value)) {
            throw new IllegalStateException("Недопустимое JSON-число: NaN или Infinity");
        }

        if (value == 0d) {
            return "0";
        }

        BigDecimal decimal = BigDecimal.valueOf(value).stripTrailingZeros();

        int exponent = decimal.precision() - decimal.scale() - 1;

        if (exponent < -6 || exponent >= 21) {
            String digits = decimal.unscaledValue().abs().toString();
            String sign = decimal.signum() < 0 ? "-" : "";
            String exponentValue = exponent >= 0 ? "+" + exponent : Integer.toString(exponent);

            if (digits.length() == 1) {
                return sign + digits + "e" + exponentValue;
            }

            return sign + digits.charAt(0) + "." + digits.substring(1) + "e" + exponentValue;
        }

        String plain = decimal.toPlainString();

        if (plain.contains(".")) {
            int end = plain.length();

            while (end > 0 && plain.charAt(end - 1) == '0') {
                end--;
            }

            if (end > 0 && plain.charAt(end - 1) == '.') {
                end--;
            }

            return plain.substring(0, end);
        }

        return plain;
    }

    private void validateIJsonNumber(JsonNode node) {
        if (!node.isIntegralNumber()) {
            return;
        }

        BigInteger value = node.bigIntegerValue();

        if (value.compareTo(MIN_SAFE_INTEGER) < 0 || value.compareTo(MAX_SAFE_INTEGER) > 0) {
            throw new IllegalStateException(
                    "Целое число выходит за безопасный диапазон I-JSON: " + value
            );
        }
    }
}