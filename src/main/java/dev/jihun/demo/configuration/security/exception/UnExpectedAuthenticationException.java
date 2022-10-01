package dev.jihun.demo.configuration.security.exception;

import org.springframework.security.core.AuthenticationException;

public class UnExpectedAuthenticationException extends AuthenticationException {

    public UnExpectedAuthenticationException(final String msg, final Throwable cause) {
        super(msg, cause);
    }

    public UnExpectedAuthenticationException(final String msg) {
        super(msg);
    }
}
