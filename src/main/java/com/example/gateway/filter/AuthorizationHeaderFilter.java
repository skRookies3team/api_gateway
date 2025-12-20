package com.example.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import org.springframework.http.HttpMethod;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    Environment env;

    public AuthorizationHeaderFilter(Environment env) {
        super(Config.class);
        this.env = env;
    }

    public static class Config {
        // Put configuration properties here
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();

            log.warn("JWT FILTER PATH = [{}]", path);

            if (HttpMethod.OPTIONS.equals(request.getMethod())) {
                return chain.filter(exchange);
            }

            // JWT 토큰 검사 없이 통과
            if (
                    path.equals("/api/users/login") ||
                            path.equals("/api/users/signup") ||
                            path.equals("/api/users/create") ||
                            path.equals("/api/users/v3/api-docs") ||
                            path.startsWith("/swagger")
            ) {
                ServerHttpRequest cleanRequest = request.mutate()
                        .headers(h -> h.remove(HttpHeaders.AUTHORIZATION))
                        .build();

                return chain.filter(exchange.mutate().request(cleanRequest).build());
            }

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
            }

            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            if (!authorizationHeader.startsWith("Bearer ")) {
                return onError(exchange, "Invalid Authorization header", HttpStatus.UNAUTHORIZED);
            }
            String jwt = authorizationHeader.substring(7);
            //jwt에서 사용자 id 추출
            JwtUser user = isJwtValid(jwt);
            if (user == null) {
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }
            //추출된 id를 요청 헤더에 추가
            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-USER-ID", user.getUserId())
                    .header("X-USER-NAME", user.getUsername())
                    .build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        log.error(err);

        byte[] bytes = "The requested token is invalid.".getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
        return response.writeWith(Flux.just(buffer));
    }

    private JwtUser isJwtValid(String jwt) {
        String secret = env.getProperty("token.secret");

        if (secret == null || secret.isBlank()) {
            log.error("JWT secret is missing. Check TOKEN_SECRET env");
            return null;
        }

        byte[] secretKeyBytes = secret.getBytes(StandardCharsets.UTF_8);

        SecretKey signingKey = new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS512.getJcaName());
        //jwt를 파싱하고 Body에서 Subject(사용자 ID)를 추출
        String userId = null;
        String username = null;

        try {
            JwtParser jwtParser = Jwts.parser()
                    .setSigningKey(signingKey)
                    .build();

            Claims claims = jwtParser.parseClaimsJws(jwt).getBody();
            userId = claims.getSubject();
            username = claims.get("username", String.class);

        } catch (Exception ex) {
            log.warn("JWT parse failed: {}", ex.getMessage());
        }

        if (userId != null && !userId.isEmpty() && username != null && !username.isEmpty()) {
            return new JwtUser(userId, username);
        }

        return null;
    }

    public static class JwtUser {
        private final String userId;
        private final String username;
        public JwtUser(String userId, String username) {
            this.userId = userId;
            this.username = username;
        }

        public String getUserId() {
            return userId;
        }

        public String getUsername() {
            return username;
        }
    }
}
