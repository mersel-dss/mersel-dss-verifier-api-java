package io.mersel.dss.verify.api.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web guvenlik yapilandirmasi.
 * 
 * Not: Bu proje su anda authentication olmadan calismaktadir.
 * Internal kullanim icin tasarlanmistir. Production ortaminda
 * network seviyesinde guvenlik saglanmalidir.
 */
@Configuration
public class SecurityConfiguration implements WebMvcConfigurer {

    @Value("${cors.allowed-origins:*}")
    private String allowedOrigins;

    @Value("${cors.allowed-methods:GET,POST,PUT,DELETE,OPTIONS}")
    private String allowedMethods;

    @Value("${cors.max-age:3600}")
    private Long maxAge;

    /**
     * Root path'i Scalar UI'ya yonlendir.
     */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addRedirectViewController("/", "/index.html");
    }

    /**
     * CORS mapping configuration.
     */
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOriginPatterns("*")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH")
                .allowedHeaders("*")
                .exposedHeaders(
                    "Content-Disposition",
                    "X-Verification-Status",
                    "X-Signature-Count",
                    "X-Signature-Valid"
                )
                .allowCredentials(false)
                .maxAge(3600);
    }
}

