package com.clarium.clarium_sso.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;
import java.util.HashMap;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<Map<String, Object>> handleEmailExists(EmailAlreadyExistsException ex) {
        return buildErrorResponse(ex);
    }

    @ExceptionHandler(UsernameAlreadyExistsException.class)
    public ResponseEntity<Map<String, Object>> handleUsernameExists(UsernameAlreadyExistsException ex) {
        return buildErrorResponse(ex);
    }

    @ExceptionHandler(NotAnEmployeeException.class)
    public ResponseEntity<Map<String, Object>> handleNotEmployee(NotAnEmployeeException ex) {
        return buildErrorResponse(ex);
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNotFound(ResourceNotFoundException ex) {
        return buildErrorResponse(ex);
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidCredentials(InvalidCredentialsException ex) {
        return buildErrorResponse(ex);
    }

    @ExceptionHandler(BaseException.class)
    public ResponseEntity<Map<String, Object>> handleBaseException(BaseException ex) {
        return buildErrorResponse(ex);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleOthers(Exception ex) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "Internal server error - " + ex.getMessage());
        errorResponse.put("status", "FAILED");
        errorResponse.put("timestamp", java.time.Instant.now().toString());

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }

    private ResponseEntity<Map<String, Object>> buildErrorResponse(BaseException ex) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("id", ex.getId());
        errorResponse.put("error", ex.getExceptionMessage() != null ? ex.getExceptionMessage() : ex.getMessage());
        errorResponse.put("errorCode", ex.getErrorCode());
        errorResponse.put("errorModule", ex.getErrorModule());
        errorResponse.put("status", ex.getStatus() != null ? ex.getStatus() : "FAILED");
        errorResponse.put("timestamp", ex.getTimeStamp());

        HttpStatus httpStatus = ex.getHttpStatus() != null ? ex.getHttpStatus() : HttpStatus.INTERNAL_SERVER_ERROR;

        return ResponseEntity.status(httpStatus).body(errorResponse);
    }
}