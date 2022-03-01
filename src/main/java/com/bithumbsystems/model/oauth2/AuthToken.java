package com.bithumbsystems.model.oauth2;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthToken {
    private String access_token;
    private String token_type;
    private String refresh_token;
    private long expires_in;
    private String scope;
}

