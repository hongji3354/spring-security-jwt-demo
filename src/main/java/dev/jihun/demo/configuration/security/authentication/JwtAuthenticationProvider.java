package dev.jihun.demo.configuration.security.authentication;

import dev.jihun.demo.configuration.security.exception.PasswordNotMatchException;
import dev.jihun.demo.configuration.security.exception.RefreshTokenExpiredException;
import dev.jihun.demo.configuration.security.exception.TokenMalformedException;
import dev.jihun.demo.configuration.security.exception.TokenSignatureException;
import dev.jihun.demo.configuration.security.exception.UnExpectedAuthenticationException;
import dev.jihun.demo.configuration.security.jwt.TokenProvider;
import dev.jihun.demo.user.entity.UserToken;
import dev.jihun.demo.user.service.UserTokenService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final UserTokenService userTokenService;
    private final PasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        BearerTokenAuthenticationToken bearerTokenAuthenticationToken = (BearerTokenAuthenticationToken) authentication;

        if (bearerTokenAuthenticationToken.isAccessTokenRenewal()) {
            return refreshTokenLogin(bearerTokenAuthenticationToken);
        }

        return usernamePasswordLogin(bearerTokenAuthenticationToken);
    }

    private BearerTokenAuthenticationToken refreshTokenLogin(final BearerTokenAuthenticationToken bearerTokenAuthenticationToken) {
        final Token userToken = bearerTokenAuthenticationToken.getUserToken();

        try {
            tokenProvider.verify(userToken.getRefreshToken());
            return getRenewalAccessToken(userToken);
        } catch (SignatureException signatureException) {
            throw new TokenSignatureException("token signature invalid", signatureException);
        } catch (MalformedJwtException malformedJwtException) {
            throw new TokenMalformedException("malformed token", malformedJwtException);
        } catch (ExpiredJwtException expiredJwtException) {
            return getRenewalAccessToken(userToken);
        } catch (Exception e) {
            throw new UnExpectedAuthenticationException("unexpected authentication exception", e);
        }
    }

    private BearerTokenAuthenticationToken usernamePasswordLogin(final BearerTokenAuthenticationToken bearerTokenAuthenticationToken) {
        final String username = (String) bearerTokenAuthenticationToken.getPrincipal();
        final String rowPassword = (String) bearerTokenAuthenticationToken.getCredentials();

        final DemoUserDetails userDetails = (DemoUserDetails) userDetailsService.loadUserByUsername(username);

        if (!passwordEncoder.matches(rowPassword, userDetails.getPassword())) {
            throw new PasswordNotMatchException("password not match");
        }

        final HashMap<String, Object> payload = getPayload(userDetails.getUserId());
        final Token token = tokenProvider.createToken(payload);
        log.info("token : {}", token);

        userTokenService.saveToken(userDetails.getUserId(), token.getRefreshToken());

        return new BearerTokenAuthenticationToken(token, true);
    }

    private BearerTokenAuthenticationToken getRenewalAccessToken(final Token userToken) {
        try {
            final UserToken findUserToken = userTokenService.findRefreshToken(userToken.getRefreshToken());
            tokenProvider.verify(findUserToken.getRefreshToken());
            final Token token = tokenProvider.createToken(getPayload(findUserToken.getUser().getId()));
            log.info("token : {}", token);

            findUserToken.changeRefreshToken(token.getRefreshToken());
            userTokenService.updateToken(findUserToken);

            return new BearerTokenAuthenticationToken(token);
        } catch (ExpiredJwtException expiredRefreshJwtException) {
            throw new RefreshTokenExpiredException("refreshToken Expired", expiredRefreshJwtException);
        }
    }

    private static HashMap<String, Object> getPayload(Long userId) {
        final HashMap<String, Object> payload = new HashMap<>();
        payload.put("userId", userId);
        return payload;
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return authentication.isAssignableFrom(BearerTokenAuthenticationToken.class);
    }
}
