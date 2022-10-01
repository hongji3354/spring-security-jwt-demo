package dev.jihun.demo.configuration.security.exception;

import org.springframework.security.core.AuthenticationException;

public class TokenSignatureException extends AuthenticationException {

    public TokenSignatureException(final String msg, final Throwable cause) {
        super(msg, cause);
    }

    public TokenSignatureException(final String msg) {
        super(msg);
    }
}
