package com.spare.common.validation;

import org.springframework.util.StringUtils;

import java.math.BigDecimal;
import java.util.regex.Pattern;

public final class ValidationUtil {

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
    );

    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d@$!%*#?&]{8,}$"
    );

    private ValidationUtil() {
        // 인스턴스 생성 방지
    }

    public static boolean isValidEmail(String email) {
        return StringUtils.hasText(email) && EMAIL_PATTERN.matcher(email).matches();
    }

    public static boolean isValidPassword(String password) {
        return StringUtils.hasText(password) && PASSWORD_PATTERN.matcher(password).matches();
    }

    public static boolean isValidProductName(String name) {
        return StringUtils.hasText(name) && name.trim().length() >= 2 && name.trim().length() <= 100;
    }

    public static boolean isValidBrand(String brand) {
        return StringUtils.hasText(brand) && brand.trim().length() >= 1 && brand.trim().length() <= 50;
    }

    public static boolean isValidCategory(String category) {
        return StringUtils.hasText(category) && category.trim().length() >= 1 && category.trim().length() <= 50;
    }

    public static boolean isValidPrice(BigDecimal price) {
        return price != null && price.compareTo(BigDecimal.ZERO) > 0;
    }

    public static String sanitizeString(String input) {
        if (!StringUtils.hasText(input)) {
            return input;
        }
        return input.trim();
    }
}