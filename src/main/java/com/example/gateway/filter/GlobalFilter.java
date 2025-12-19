package com.example.gateway.filter;


import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import lombok.Data;
@Component
@Slf4j
public class GlobalFilter extends AbstractGatewayFilterFactory<GlobalFilter.Config> {
//AbstractGatewayFilterFactory: GateWay를 구현하려면 GateWayFilterFactory를 구현해야 한다.
//<Config>: 설정 파일(application.yaml)에서 받을 설정값들의 구조를 정의한다.
// key-value 쌍 형태의 설정을 받아 사용하는 커스텀 필터를 만들때 상속하는 클래스이다.
    public GlobalFilter() {
        super(Config.class);
    }

    @Override
    //Config 객체를 받아 실제 필터 로직을 담은 GatewayFilter 객체를 반환한다.
    public GatewayFilter apply(Config config) {

        //exchange: 서비스 요청/응답값을 담는 변수이다. 요청/응답값을 출력하거나 변환할 때 사용한다.
        //요청값은 (exchange, chain) 구문 이후에 얻을 수 있다.
        //응답값은 Mono.fromRunnable(() -> 구문 이후에 얻을 수 있다.
        return (((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            //pre-filter 로직(요청 처리 전)
            //config의 baseMessage와 요청의 발신지 ip를 로그로 출력한다.
            log.info("Global Filter baseMessage: {}, {}", config.getBaseMessage(), request.getRemoteAddress());

            if (config.isPreLogger()) {
                log.info("Global Filter Start: request id -> {}", request.getId());
            }

            //요청을 다음 필터/라우팅으로 전달
            return chain.filter(exchange).then(Mono.fromRunnable(()->{

                //post-filter 로직(응답 처리 후)
                //응답의 상태 코드를 출력한다.
                if (config.isPostLogger()) {
                    log.info("Global Filter End: response code -> {}", response.getStatusCode());
                }
            }));

        }));
    }

    @Data
    //필터가 사용할 application.yml 설정값을 정의한다.
    public static class Config {
        private String baseMessage;
        private boolean preLogger;
        private boolean postLogger;
    }
}
