package com.simo.oauth2.authenticationserver.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("user.oauth")
public class UserProperties {

    private String clientId;
    private String clientSecret;


    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }
}
