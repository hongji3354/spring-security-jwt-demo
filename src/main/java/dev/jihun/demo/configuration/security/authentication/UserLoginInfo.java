package dev.jihun.demo.configuration.security.authentication;

import lombok.Getter;

@Getter
public class UserLoginInfo {

    private String username;
    private String password;

    public boolean valid() {
        return (this.username == null || this.password == null);
    }
}
