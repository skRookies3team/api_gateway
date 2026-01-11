package com.example.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

/**
 * JWT 인증 필터
 * WHY: Gateway에서 JWT 토큰을 검증하고 사용자 정보를 헤더에 추가
 */
@Component
@Slf4j
public class AuthorizationHeaderFilter
        extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    Environment env;

    public AuthorizationHeaderFilter(Environment env) {
        super(Config.class);
        this.env = env;
    }

    /**
     * 필터 이름 반환
     * WHY: application.yaml에서 "AuthorizationHeaderFilter"로 참조할 수 있도록 설정
     */
    @Override
    public String name() {
        return "AuthorizationHeaderFilter";
    }

    /**
     * Filter 설정 클래스
     * WHY: AbstractGatewayFilterFactory 제네릭 타입으로 필요
     * NOTE: Spring Cloud Gateway 2025.0.0에서는 클래스명이 "Config"여야 함
     */
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

            // JWT 검사 없이 통과
            if (path.equals("/api/health") ||
                    path.startsWith("/api/health/") ||
                    path.equals("/api/chat/health") ||
                    path.equals("/api/users/login") ||
                    path.equals("/api/users/signup") ||
                    path.equals("/api/users/create") ||
                    path.equals("/api/users/v3/api-docs") ||
                    path.startsWith("/swagger")) {
                ServerHttpRequest cleanRequest = request.mutate()
                        .headers(h -> h.remove(HttpHeaders.AUTHORIZATION))
                        .build();

                return chain.filter(exchange.mutate().request(cleanRequest).build());
            }

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                // [디버깅] 실제 들어온 헤더 출력
                log.error("No authorization header for path: {}", path);
                log.error("Request Headers: {}", request.getHeaders().keySet());
                log.error("Origin: {}", request.getHeaders().getFirst("Origin"));
                return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
            }

            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            if (!authorizationHeader.startsWith("Bearer ")) {
                return onError(exchange, "Invalid Authorization header", HttpStatus.UNAUTHORIZED);
            }
            String jwt = authorizationHeader.substring(7);

            JwtUser user = isJwtValid(jwt);
            if (user == null) {
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

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

    /**
     * JWT 토큰 검증 (JJWT 0.11.5 호환)
     * WHY: User Service에서 발급한 JWT 토큰을 검증
     */
    private JwtUser isJwtValid(String jwt) {
        String secret = env.getProperty("token.secret");

        if (secret == null || secret.isBlank()) {
            log.error("JWT secret is missing. Check TOKEN_SECRET env");
            return null;
        }

        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

        String userId = null;
        String username = null;

        try {
            // JJWT 0.11.5 API 사용
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(jwt)
                    .getBody();

            // subject에서 userId 추출
            userId = claims.getSubject();

            // username은 여러 가지 클레임명으로 시도
            username = claims.get("username", String.class);
            if (username == null) {
                username = claims.get("name", String.class);
            }
            if (username == null) {
                username = claims.get("email", String.class);
            }
            if (username == null) {
                username = "user_" + userId; // 기본값 설정
            }

            log.debug("JWT parsed - userId: {}, username: {}", userId, username);

        } catch (io.jsonwebtoken.ExpiredJwtException ex) {
            log.warn("JWT expired: {}", ex.getMessage());
            return null;
        } catch (io.jsonwebtoken.security.SignatureException ex) {
            log.warn("JWT signature invalid: {}", ex.getMessage());
            return null;
        } catch (Exception ex) {
            log.warn("JWT parse failed: {}", ex.getMessage());
            return null;
        }

        // userId만 있으면 통과 (username은 기본값 사용)
        if (userId != null && !userId.isEmpty()) {
            return new JwtUser(userId, username);
        }

        log.warn("JWT userId is empty");
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
