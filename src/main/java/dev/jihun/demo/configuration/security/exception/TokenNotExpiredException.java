package dev.jihun.demo.configuration.security.exception;

import org.springframework.security.core.AuthenticationException;

public class TokenNotExpiredException extends AuthenticationException {

    public TokenNotExpiredException(final String msg, final Throwable cause) {
        super(msg, cause);
    }

    public TokenNotExpiredException(final String msg) {
        super(msg);
    }
}
