package com.clarium.clarium_sso.exception;

public class UsernameAlreadyExistsException extends  RuntimeException {
    public UsernameAlreadyExistsException(String message) {
        super(message);
    }
}
