package com.clarium.clarium_sso.exception;

import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.http.HttpStatus;

import java.io.Serial;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import org.apache.commons.lang3.RandomUtils;

@EqualsAndHashCode(callSuper = true)
@Data
public class BaseException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    private int id = RandomUtils.nextInt(5000, 10000);
    private HttpStatus httpStatus;
    private String status;
    private String errorCode;
    private String errorModule;
    private String exceptionMessage;
    private String timeStamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss")
            .format(new Timestamp(System.currentTimeMillis()));

    // Default constructor
    public BaseException() {
        super();
    }

    // Constructor with message only (calls RuntimeException constructor)
    public BaseException(String message) {
        super(message);
        this.exceptionMessage = message;
    }

    // Constructor with message and cause
    public BaseException(String message, Throwable cause) {
        super(message, cause);
        this.exceptionMessage = message;
    }

    // Constructor with cause only
    public BaseException(Throwable cause) {
        super(cause);
        this.exceptionMessage = cause.getMessage();
    }

    // Constructor with errorCode and message
    public BaseException(String errorCode, String exceptionMessage) {
        super(exceptionMessage);
        this.id = RandomUtils.nextInt(1001, 5000);
        this.errorCode = errorCode;
        this.exceptionMessage = exceptionMessage;
    }

    // Constructor with errorCode, errorModule, and message
    public BaseException(String errorCode, String errorModule, String exceptionMessage) {
        super(exceptionMessage);
        this.errorCode = errorCode;
        this.errorModule = errorModule;
        this.exceptionMessage = exceptionMessage;
    }

    // Constructor with HttpStatus, errorCode, and message
    public BaseException(HttpStatus httpStatus, String errorCode, String exceptionMessage) {
        super(exceptionMessage);
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
        this.exceptionMessage = exceptionMessage;
    }

    // Constructor with HttpStatus, errorCode, errorModule, message, and status
    public BaseException(HttpStatus httpStatus, String errorCode, String errorModule,
                         String exceptionMessage, String status) {
        super(exceptionMessage);
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
        this.errorModule = errorModule;
        this.exceptionMessage = exceptionMessage;
        this.status = status;
    }

    // Constructor with HttpStatus and errorCode
    public BaseException(HttpStatus httpStatus, String errorCode) {
        super();
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
    }

    // Constructor with HttpStatus, errorCode, message, and timestamp
    public BaseException(HttpStatus httpStatus, String errorCode, String exceptionMessage, String timeStamp) {
        super(exceptionMessage);
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
        this.exceptionMessage = exceptionMessage;
        this.timeStamp = timeStamp;
    }
}