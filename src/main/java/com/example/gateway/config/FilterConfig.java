package com.example.gateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

//@Configuration
public class FilterConfig {
    //라우팅 규칙과 필터를 정의한다. application.yml과 기능은 동일하지만
    //프로그래밍 방식으로 제어할 수 있다는 장점이 있다.

    //환경 변수를 담는 객체이다. 이 객체를 통해 설정 파일이나
    //시스템 환경 변수에 접근할 수 있다.
    Environment env;

    public FilterConfig(Environment env) {
        this.env = env;
    }

    //@Bean
    //라우팅 정보를 찾아주는 인터페이스이다.
    public RouteLocator getRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                //라우팅 규칙을 정의한다.
                .route(r -> r.path("/api/users/**")
                        //filters: 라우팅이 결정된 후 서비스로 가기 전/후에 적용할 필터를 정의한다.
                        //addRequestHeader: 요청이 서비스로 가기 전에 헤더 추가
                        //addResponseHeader: 응답이 서비스에서 돌아온 후에 헤더 추가
                        .filters(f -> f.addRequestHeader("user-request", "user-request-header-by-java")
                                .addResponseHeader("user-response", "1st-response-header-from-java"))
                        //요청을 보낼 uri 지정
                        .uri("http://localhost:8081"))
                .build();
    }
}
