package dev.jihun.demo.configuration.security.web.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.jihun.demo.configuration.security.authentication.Token;
import dev.jihun.demo.configuration.security.authentication.UserLoginInfo;
import dev.jihun.demo.configuration.security.authentication.BearerTokenAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StreamUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private final AuthenticationManager authenticationManager;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final AuthenticationFailureHandler authenticationFailureHandler;

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response, final FilterChain filterChain) throws ServletException, IOException {
        if (!isSupportHttpMethod(request)) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        if (!isSupportContentType(request)) {
            throw new AuthenticationServiceException("Authentication media Type not supported: " + request.getContentType());
        }

        final String refreshToken = getRefreshToken(request);

        if (isAccessTokenRenewal(refreshToken)) {
            final Token token = new Token(refreshToken);
            authenticate(request, response, new BearerTokenAuthenticationToken(token));
        } else {
            final UserLoginInfo userLoginInfo = getUserLoginInfo(request);
            authenticate(request, response, new BearerTokenAuthenticationToken(userLoginInfo));
        }
    }

    private void authenticate(final HttpServletRequest request, final HttpServletResponse response, final BearerTokenAuthenticationToken bearerTokenAuthenticationToken) throws IOException, ServletException {
        try {
            final Authentication authenticate = authenticationManager.authenticate(bearerTokenAuthenticationToken);
            //SecurityContextHolder.getContext().setAuthentication(authenticate);
            authenticationSuccessHandler.onAuthenticationSuccess(request, response, authenticate);
        } catch (AuthenticationException authenticationException) {
            //SecurityContextHolder.clearContext();
            authenticationFailureHandler.onAuthenticationFailure(request, response, authenticationException);
        }
    }

    private static UserLoginInfo getUserLoginInfo(final HttpServletRequest request) throws IOException {
        String messageBody = getHttpBody(request);
        final ObjectMapper mapper = new ObjectMapper();

        final UserLoginInfo userLoginInfo = mapper.readValue(messageBody, UserLoginInfo.class);

        if (userLoginInfo.valid()) {
            throw new AuthenticationServiceException("Insufficient authentication information");
        }
        return userLoginInfo;
    }

    private static String getHttpBody(final HttpServletRequest request) throws IOException {
        ServletInputStream inputStream = request.getInputStream();
        String messageBody = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
        return messageBody;
    }

    private static boolean isAccessTokenRenewal(final String refreshToken) {
        return refreshToken != null;
    }

    private static boolean isSupportContentType(final HttpServletRequest request) {
        return request.getContentType() != null || request.getContentType().equalsIgnoreCase(MediaType.APPLICATION_JSON_VALUE);
    }

    private static boolean isSupportHttpMethod(final HttpServletRequest request) {
        return request.getMethod().equalsIgnoreCase(HttpMethod.POST.name());
    }

    private String getRefreshToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
