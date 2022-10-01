package dev.jihun.demo.configuration.security.authentication;

import org.springframework.security.authentication.AuthenticationServiceException;

public class Token {

    private String accessToken;
    private String refreshToken;

    public Token(String accessToken, String refreshToken) {
        if (accessToken == null || refreshToken == null) {
            throw new IllegalArgumentException();
        }
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public Token(String refreshToken) {
        if (refreshToken == null) {
            throw new AuthenticationServiceException("refreshToken is null");
        }
        this.refreshToken=refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    @Override
    public String toString() {
        return "Token{" +
                "accessToken='" + accessToken + '\'' +
                ", refreshToken='" + refreshToken + '\'' +
                '}';
    }
}
