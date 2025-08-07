package com.clarium.clarium_sso.exception;

import org.springframework.http.HttpStatus;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import org.apache.commons.lang3.RandomUtils;

public class BaseException extends RuntimeException{

    private static final long serialVersionUID = 1L;

    private int id = RandomUtils.nextInt(5000, 10000);
    private HttpStatus httpStatus;
    private String status;
    private String errorCode;
    private String errorModule;
    private String exceptionMessage;
    private String timeStamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss")
            .format(new Timestamp(System.currentTimeMillis()));

    public BaseException(String errorCode, String errorModule, String exceptionMessage) {
        super();
        this.errorCode = errorCode;
        this.errorModule = errorModule;
        this.exceptionMessage = exceptionMessage;
    }

    public BaseException(HttpStatus httpStatus, String errorCode, String errorModule, String exceptionMessage,
                         String status) {
        super();
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
        this.errorModule = errorModule;
        this.exceptionMessage = exceptionMessage;
        this.status = status;
    }

    public String getErrorModule() {
        return errorModule;
    }

    public void setErrorModule(String errorModule) {
        this.errorModule = errorModule;
    }

    public BaseException(HttpStatus httpStatus, String errorCode, String exceptionMessage, String timeStamp) {
        super();
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
        this.exceptionMessage = exceptionMessage;
        this.timeStamp = timeStamp;
    }

    public BaseException(HttpStatus httpStatus, String errorCode, String exceptionMessage) {
        super();
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
        this.exceptionMessage = exceptionMessage;
    }

    public BaseException(HttpStatus httpStatus, String errorCode) {
        super();
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
    }

    public BaseException(String errorCode, String exceptionMessage) {
        super();
        this.id = RandomUtils.nextInt(1001, 5000);
        this.errorCode = errorCode;
        this.exceptionMessage = exceptionMessage;
    }

    public Integer getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    public void setExceptionMessage(String exceptionMessage) {
        this.exceptionMessage = exceptionMessage;
    }

    public void setTimeStamp(String timeStamp) {
        this.timeStamp = timeStamp;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public void setHttpStatus(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getExceptionMessage() {
        return exceptionMessage;
    }

    public String getTimeStamp() {
        return timeStamp;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

}
