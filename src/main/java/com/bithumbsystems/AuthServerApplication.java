package com.bithumbsystems;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

@SpringBootApplication
public class AuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServerApplication.class, args);
    }


//    public static void main(String[] args) {
//        new SpringApplicationBuilder(AuthServerApplication.class)
//                .web(WebApplicationType.REACTIVE)
//                .run(args);
//    }
}