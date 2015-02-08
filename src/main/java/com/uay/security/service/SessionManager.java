package com.uay.security.service;

import com.uay.security.entity.SecurityToken;
import com.uay.security.util.SecurityTokenUtil;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class SessionManager {

    @Autowired
    private UserDetailsManager userDetailsManager;

    private final Map<String, String> loggedInUsers = new HashMap<>();

    public void addSession(String token) {
        SecurityToken securityToken = SecurityTokenUtil.decodeToken(token);
        if (StringUtils.isNotEmpty(securityToken.getUsername()) &&
                StringUtils.isNotEmpty(securityToken.getSignature())) {
            loggedInUsers.put(securityToken.getUsername(), securityToken.getSignature());
        }
    }

    public boolean hasLoggedIn(SecurityToken securityToken) {
        if (SecurityTokenUtil.isTokenExpired(securityToken.getExpirationDate())) {
            removeSession(securityToken.getUsername());
        }
        String controlSignature = loggedInUsers.get(securityToken.getUsername());
        return (controlSignature != null && controlSignature.equals(securityToken.getSignature()));
    }

    public void removeSession(String userName) {
        loggedInUsers.remove(userName);
    }

    public void removeSession(Authentication authentication) {
        removeSession(userDetailsManager.retrieveUsername(authentication));
    }


}
