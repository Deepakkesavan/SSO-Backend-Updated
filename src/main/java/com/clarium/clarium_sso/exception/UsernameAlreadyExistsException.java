package com.clarium.clarium_sso.exception;

import org.springframework.http.HttpStatus;

public class UsernameAlreadyExistsException extends BaseException {

    private static final String ERROR_CODE = "USERNAME_EXISTS";
    private static final String ERROR_MODULE = "USER_REGISTRATION";

    public UsernameAlreadyExistsException(String message) {
        super(HttpStatus.BAD_REQUEST, ERROR_CODE, ERROR_MODULE, message, "FAILED");
    }

    public UsernameAlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
        setHttpStatus(HttpStatus.BAD_REQUEST);
        setErrorCode(ERROR_CODE);
        setErrorModule(ERROR_MODULE);
        setStatus("FAILED");
    }

    public UsernameAlreadyExistsException(String errorCode, String message) {
        super(HttpStatus.BAD_REQUEST, errorCode, ERROR_MODULE, message, "FAILED");
    }
}