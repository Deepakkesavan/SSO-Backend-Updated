package com.clarium.clarium_sso.exception;

import org.springframework.http.HttpStatus;

public class InvalidCredentialsException extends BaseException {

    private static final String ERROR_CODE = "INVALID_CREDENTIALS";
    private static final String ERROR_MODULE = "AUTHENTICATION";

    public InvalidCredentialsException(String message) {
        super(HttpStatus.UNAUTHORIZED, ERROR_CODE, ERROR_MODULE, message, "FAILED");
    }

    public InvalidCredentialsException(String message, Throwable cause) {
        super(message, cause);
        setHttpStatus(HttpStatus.UNAUTHORIZED);
        setErrorCode(ERROR_CODE);
        setErrorModule(ERROR_MODULE);
        setStatus("FAILED");
    }

    public InvalidCredentialsException(String errorCode, String message) {
        super(HttpStatus.UNAUTHORIZED, errorCode, ERROR_MODULE, message, "FAILED");
    }
}