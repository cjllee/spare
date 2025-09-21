package com.spare.common.exception;

import com.spare.common.exception.product.ProductException;
import com.spare.common.exception.user.UserException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(UserException.EmailAlreadyExistsException.class)
    public ResponseEntity<Map<String, Object>> handleEmailAlreadyExists(UserException.EmailAlreadyExistsException e) {
        logger.warn("Email already exists attempt: {}", e.getMessage());
        return createErrorResponse(HttpStatus.CONFLICT, "EMAIL_ALREADY_EXISTS", e.getMessage());
    }

    @ExceptionHandler(UserException.UserNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleUserNotFound(UserException.UserNotFoundException e) {
        logger.warn("User not found: {}", e.getMessage());
        return createErrorResponse(HttpStatus.NOT_FOUND, "USER_NOT_FOUND", e.getMessage());
    }

    @ExceptionHandler(UserException.InvalidPasswordException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidPassword(UserException.InvalidPasswordException e) {
        logger.warn("Invalid password attempt: {}", e.getMessage());
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "INVALID_PASSWORD", e.getMessage());
    }

    @ExceptionHandler(UserException.VerificationRequiredException.class)
    public ResponseEntity<Map<String, Object>> handleVerificationRequired(UserException.VerificationRequiredException e) {
        logger.warn("Verification required: {}", e.getMessage());
        return createErrorResponse(HttpStatus.PRECONDITION_REQUIRED, "VERIFICATION_REQUIRED", e.getMessage());
    }

    @ExceptionHandler(UserException.VerificationFailedException.class)
    public ResponseEntity<Map<String, Object>> handleVerificationFailed(UserException.VerificationFailedException e) {
        logger.warn("Verification failed: {}", e.getMessage());
        return createErrorResponse(HttpStatus.BAD_REQUEST, "VERIFICATION_FAILED", e.getMessage());
    }

    @ExceptionHandler(ProductException.ProductNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleProductNotFound(ProductException.ProductNotFoundException e) {
        logger.warn("Product not found: {}", e.getMessage());
        return createErrorResponse(HttpStatus.NOT_FOUND, "PRODUCT_NOT_FOUND", e.getMessage());
    }

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<Map<String, Object>> handleBusinessException(BusinessException e) {
        logger.warn("Business exception: {} - {}", e.getErrorCode(), e.getMessage());
        return createErrorResponse(HttpStatus.BAD_REQUEST, e.getErrorCode(), e.getMessage());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException e) {
        logger.warn("Illegal argument: {}", e.getMessage());
        return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_ARGUMENT", e.getMessage());
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> handleRuntimeException(RuntimeException e) {
        logger.error("Unexpected runtime exception: {}", e.getMessage(), e);
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "서버 내부 오류가 발생했습니다");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(Exception e) {
        logger.error("Unexpected exception: {}", e.getMessage(), e);
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "서버 내부 오류가 발생했습니다");
    }

    private ResponseEntity<Map<String, Object>> createErrorResponse(HttpStatus status, String errorCode, String message) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("status", status.value());
        errorResponse.put("error", status.getReasonPhrase());
        errorResponse.put("errorCode", errorCode);
        errorResponse.put("message", message);

        return new ResponseEntity<>(errorResponse, status);
    }
}