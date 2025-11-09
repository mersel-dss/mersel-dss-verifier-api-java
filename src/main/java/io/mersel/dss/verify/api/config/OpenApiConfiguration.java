package io.mersel.dss.verify.api.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;


@Configuration
public class OpenApiConfiguration {
    @Bean
    public OpenAPI CustomOpenApiBean() {
        return new OpenAPI().components(new Components())
                .info(new Info()
                        .title("mersel-dss - Java Verifier API - Serverside")
                        .version("v0.1.0")
                        .description("[https://github.com/mersel-dss/mersel-dss-verifier-api-java](https://github.com/mersel-dss/mersel-dss-verifier-api-java)"));
    }
}