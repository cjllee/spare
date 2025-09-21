package com.spare.common.exception.user;

import com.spare.common.exception.BusinessException;

public class UserException extends BusinessException {

    public UserException(String message) {
        super("USER_ERROR", message);
    }

    public static class EmailAlreadyExistsException extends UserException {
        public EmailAlreadyExistsException() {
            super("이미 존재하는 이메일입니다");
        }
    }

    public static class UserNotFoundException extends UserException {
        public UserNotFoundException() {
            super("사용자를 찾을 수 없습니다");
        }
    }

    public static class InvalidPasswordException extends UserException {
        public InvalidPasswordException() {
            super("잘못된 비밀번호입니다");
        }
    }

    public static class VerificationRequiredException extends UserException {
        public VerificationRequiredException() {
            super("이메일 인증이 필요합니다");
        }
    }

    public static class VerificationFailedException extends UserException {
        public VerificationFailedException() {
            super("인증에 실패했습니다");
        }
    }
}
