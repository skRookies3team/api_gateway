package com.example.gateway.config;

import org.springframework.boot.web.embedded.netty.NettyReactiveWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Netty 서버 커스터마이징 설정
 * WHY: HTTP 헤더 크기 제한 증가 (TooLongHttpHeaderException 방지)
 */
@Configuration
public class NettyConfig {

    /**
     * Netty HTTP 요청 디코더 설정
     * - maxHeaderSize: 65KB (기본 16KB)
     * - maxInitialLineLength: 65KB (기본 8KB)
     */
    @Bean
    public WebServerFactoryCustomizer<NettyReactiveWebServerFactory> nettyCustomizer() {
        return factory -> factory
                .addServerCustomizers(httpServer -> httpServer.httpRequestDecoder(spec -> spec.maxHeaderSize(65536) // 64KB
                        .maxInitialLineLength(65536)));
    }
}
