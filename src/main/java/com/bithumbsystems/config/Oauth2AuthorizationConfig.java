package com.bithumbsystems.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

@Configuration
@EnableAuthorizationServer
public class Oauth2AuthorizationConfig extends AuthorizationServerConfigurerAdapter {

    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        // auth-security-id : 클라이언트에 발급한 아이디
        clients.inMemory()
                .withClient("auth-security-id")
                .secret("authSecret")
                .redirectUris("http://localhost:9001/auth/callback")
                .authorizedGrantTypes("authorization_code")
                .scopes("read", "write")
                .accessTokenValiditySeconds(30000);   // 30s
    }
}
