package com.bithumbsystems.controller;

import com.bithumbsystems.model.oauth2.AuthToken;
import com.google.gson.Gson;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base64;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;

@RequiredArgsConstructor
@RestController
@RequestMapping("/auth")
public class Oauth2Controller {

    private final Gson gson;
    private final RestTemplate restTemplate;

    @GetMapping(value="/callback")
    public AuthToken callbackSocial(@RequestParam String code) {
        String credentials = "auth-security-id:authSecret";
        String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", "Basic " + encodedCredentials);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("grant_type", "authorization_code");
        params.add("redirect_uri", "http://localhost:9001/auth/callback");
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<String> response = restTemplate.postForEntity("http://localhost:9001/oauth/token", request, String.class);

        if (response.getStatusCode() == HttpStatus.OK) {
            return gson.fromJson(response.getBody(), AuthToken.class);
        }
        return null;
    }
}
