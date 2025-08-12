package com.clarium.clarium_sso.exception;

import org.springframework.http.HttpStatus;
import static com.clarium.clarium_sso.constant.ExceptionConstants.ERROR_CODE;
import static com.clarium.clarium_sso.constant.ExceptionConstants.ERROR_MODULE;

public class EmailAlreadyExistsException extends BaseException {

    public EmailAlreadyExistsException(String message) {
        super(HttpStatus.BAD_REQUEST, ERROR_CODE, ERROR_MODULE, message, "FAILED");
    }

    public EmailAlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
        setHttpStatus(HttpStatus.BAD_REQUEST);
        setErrorCode(ERROR_CODE);
        setErrorModule(ERROR_MODULE);
        setStatus("FAILED");
    }

    public EmailAlreadyExistsException(String errorCode, String message) {
        super(HttpStatus.BAD_REQUEST, errorCode, ERROR_MODULE, message, "FAILED");
    }
}