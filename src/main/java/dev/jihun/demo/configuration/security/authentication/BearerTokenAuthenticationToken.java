package dev.jihun.demo.configuration.security.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class BearerTokenAuthenticationToken extends AbstractAuthenticationToken {

    private Token token;
    private Object principal;
    private Object credentials;

    public BearerTokenAuthenticationToken(final Token token) {
        super(null);
        this.token = token;
        this.setAuthenticated(false);
    }

    public BearerTokenAuthenticationToken(final Token token, final Boolean authenticated) {
        super(null);
        this.token = token;
        this.setAuthenticated(authenticated);
    }

    public BearerTokenAuthenticationToken(UserLoginInfo userLoginInfo) {
        super(null);
        this.principal = userLoginInfo.getUsername();
        this.credentials = userLoginInfo.getPassword();
        super.setAuthenticated(false);
    }

    public Token getUserToken() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    public boolean isUsernameLogin() {
        return !isAccessTokenRenewal();
    }

    public boolean isAccessTokenRenewal() {
        return this.token != null;
    }
}
