package dev.jihun.demo.user.service;

import dev.jihun.demo.user.entity.UserToken;

public interface UserTokenService {

    void saveToken(Long userId, String refreshToken);
    void updateToken(UserToken userToken);

    UserToken findRefreshToken(String refreshToken);
}
