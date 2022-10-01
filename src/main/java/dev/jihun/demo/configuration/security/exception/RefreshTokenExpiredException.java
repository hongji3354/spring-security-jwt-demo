package dev.jihun.demo.configuration.security.exception;

import org.springframework.security.core.AuthenticationException;

public class RefreshTokenExpiredException extends AuthenticationException {

    public RefreshTokenExpiredException(final String msg, final Throwable cause) {
        super(msg, cause);
    }

    public RefreshTokenExpiredException(final String msg) {
        super(msg);
    }
}
