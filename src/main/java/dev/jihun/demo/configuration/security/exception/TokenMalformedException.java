package dev.jihun.demo.configuration.security.exception;

import org.springframework.security.core.AuthenticationException;

public class TokenMalformedException extends AuthenticationException {

    public TokenMalformedException(final String msg, final Throwable cause) {
        super(msg, cause);
    }

    public TokenMalformedException(final String msg) {
        super(msg);
    }
}
