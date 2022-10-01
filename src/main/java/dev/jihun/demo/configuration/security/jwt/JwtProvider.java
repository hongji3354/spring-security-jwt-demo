package dev.jihun.demo.configuration.security.jwt;

import dev.jihun.demo.configuration.security.authentication.Token;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import org.springframework.beans.factory.annotation.Value;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtProvider implements TokenProvider {

    private static final String TOKEN_TYPE = "JWT";
    private static final SignatureAlgorithm TOKEN_ALGORITHM = SignatureAlgorithm.HS256;

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expired.accessToken}")
    private Long accessTokenExpiredMinute;

    @Value("${jwt.expired.refreshToken}")
    private Long refreshTokenExpiredMinute;

    @Override
    public Token createToken(Map<String, Object> payload) {
        final JwtBuilder jwtBuilder = Jwts.builder()
                .setHeader(createHeader())
                .setClaims(payload)
                .signWith(SignatureAlgorithm.HS256, getBase64EncodedSecretKey());

        final LocalDateTime accessTokenExpiredDatetime = LocalDateTime.now().plusMinutes(accessTokenExpiredMinute);
        final LocalDateTime refreshTokenExpiredDatetime = LocalDateTime.now().plusMinutes(refreshTokenExpiredMinute);

        final String accessToken = jwtBuilder
                .setExpiration(new Date(accessTokenExpiredDatetime.atZone(ZoneId.of("Asia/Seoul")).toInstant().toEpochMilli()))
                .compact();

        final String refreshToken = jwtBuilder
                .setExpiration(new Date(refreshTokenExpiredDatetime.atZone(ZoneId.of("Asia/Seoul")).toInstant().toEpochMilli()))
                .compact();

        return new Token(accessToken, refreshToken);
    }

    private Map<String, Object> createHeader() {
        Map<String, Object> headers = new HashMap<>();
        headers.put("typ", TOKEN_TYPE);
        headers.put("alg", TOKEN_ALGORITHM.getValue());

        return headers;
    }

    @Override
    public void verify(final String token) {
        try {
            Jwts.parser()
                    .setSigningKey(getBase64EncodedSecretKey())
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException expiredJwtException) {

        } catch (SignatureException signatureException) {

        } catch (MalformedJwtException malformedJwtException) {

        } catch (Exception exception) {

        }
    }

    private byte[] getBase64EncodedSecretKey() {
        return Base64.getEncoder().encode(secretKey.getBytes(StandardCharsets.UTF_8));
    }
}
