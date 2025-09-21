package com.spare.common.constants;

public final class ValidationConstants {
    public static final int VERIFICATION_CODE_LENGTH = 6;
    public static final long VERIFICATION_CODE_EXPIRE_MINUTES = 10;
    public static final long VERIFIED_STATUS_EXPIRE_MINUTES = 30;
    public static final String VERIFICATION_KEY_PREFIX = "verification:";
    public static final String VERIFIED_KEY_PREFIX = "verified:";

    private ValidationConstants() {
        // 인스턴스 생성 방지
    }
}