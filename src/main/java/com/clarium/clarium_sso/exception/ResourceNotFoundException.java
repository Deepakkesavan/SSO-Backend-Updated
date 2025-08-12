package com.clarium.clarium_sso.exception;

import org.springframework.http.HttpStatus;

public class ResourceNotFoundException extends BaseException {

    private static final String ERROR_CODE = "RESOURCE_NOT_FOUND";
    private static final String ERROR_MODULE = "DATA_ACCESS";

    public ResourceNotFoundException(String message) {
        super(HttpStatus.NOT_FOUND, ERROR_CODE, ERROR_MODULE, message, "FAILED");
    }

    public ResourceNotFoundException(String message, Throwable cause) {
        super(message, cause);
        setHttpStatus(HttpStatus.NOT_FOUND);
        setErrorCode(ERROR_CODE);
        setErrorModule(ERROR_MODULE);
        setStatus("FAILED");
    }

    public ResourceNotFoundException(String errorCode, String message) {
        super(HttpStatus.NOT_FOUND, errorCode, ERROR_MODULE, message, "FAILED");
    }

    public ResourceNotFoundException(String errorModule, String errorCode, String message) {
        super(HttpStatus.NOT_FOUND, errorCode, errorModule, message, "FAILED");
    }
}