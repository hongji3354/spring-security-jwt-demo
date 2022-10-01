package dev.jihun.demo.user.service;

import dev.jihun.demo.user.entity.User;
import dev.jihun.demo.user.entity.UserRepository;
import dev.jihun.demo.user.entity.UserToken;
import dev.jihun.demo.user.entity.UserTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;

@Transactional
@RequiredArgsConstructor
public class UserTokenServiceImpl implements UserTokenService {

    private final UserRepository userRepository;
    private final UserTokenRepository userTokenRepository;

    public void saveToken(Long userId, String refreshToken) {
        final User user = userRepository.findById(userId)
                .orElseThrow(IllegalArgumentException::new);

        user.addUserToken(refreshToken);
    }

    @Override
    public void updateToken(final UserToken userToken) {
        userTokenRepository.save(userToken);
    }

    @Override
    @Transactional(readOnly = true)
    public UserToken findRefreshToken(final String refreshToken) {
        return userTokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(IllegalArgumentException::new);
    }
}
