package dev.jihun.demo.user.service;

import dev.jihun.demo.configuration.security.authentication.DemoUserDetails;
import dev.jihun.demo.user.entity.User;
import dev.jihun.demo.user.entity.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        final User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    throw new UsernameNotFoundException("user not found");
                });

        return new DemoUserDetails(user);
    }
}
