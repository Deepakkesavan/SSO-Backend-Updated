package com.clarium.clarium_sso.exception;

import org.springframework.http.HttpStatus;

public class NotAnEmployeeException extends BaseException {

    private static final String ERROR_CODE = "NOT_AN_EMPLOYEE";
    private static final String ERROR_MODULE = "AUTHENTICATION";

    public NotAnEmployeeException(String message) {
        super(HttpStatus.FORBIDDEN, ERROR_CODE, ERROR_MODULE, message, "FAILED");
    }

    public NotAnEmployeeException(String message, Throwable cause) {
        super(message, cause);
        setHttpStatus(HttpStatus.FORBIDDEN);
        setErrorCode(ERROR_CODE);
        setErrorModule(ERROR_MODULE);
        setStatus("FAILED");
    }

    public NotAnEmployeeException(String errorCode, String message) {
        super(HttpStatus.FORBIDDEN, errorCode, ERROR_MODULE, message, "FAILED");
    }
}