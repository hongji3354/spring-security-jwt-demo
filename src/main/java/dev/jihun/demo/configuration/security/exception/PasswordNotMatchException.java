package dev.jihun.demo.configuration.security.exception;

import org.springframework.security.core.AuthenticationException;

public class PasswordNotMatchException extends AuthenticationException {

    public PasswordNotMatchException(final String msg, final Throwable cause) {
        super(msg, cause);
    }

    public PasswordNotMatchException(final String msg) {
        super(msg);
    }
}
