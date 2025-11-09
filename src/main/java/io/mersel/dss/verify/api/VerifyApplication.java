package io.mersel.dss.verify.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Mersel DSS Verify API - Dijital Imza Dogrulama Servisi
 * 
 * Bu uygulama PAdES ve XAdES imzalarin dogrulanmasi icin
 * kapsamli bir servis saglar.
 */
@SpringBootApplication
@EnableScheduling
public class VerifyApplication {

    public static void main(String[] args) {
        SpringApplication.run(VerifyApplication.class, args);
    }
}

