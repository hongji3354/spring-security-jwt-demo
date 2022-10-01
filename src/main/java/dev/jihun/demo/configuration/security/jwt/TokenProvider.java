package dev.jihun.demo.configuration.security.jwt;

import dev.jihun.demo.configuration.security.authentication.Token;

import java.util.Map;

public interface TokenProvider {

    Token createToken(Map<String, Object> payload);
    void verify(String token);
}
