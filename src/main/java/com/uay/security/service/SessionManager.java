package com.uay.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class SessionManager {

    @Autowired
    private UserDetailsManager userDetailsManager;

    private final Set<String> loggedInUsers = new HashSet<>();

    public void addSession(String userName) {
        loggedInUsers.add(userName);
    }

    public boolean hasLoggedIn(String userName) {
        return loggedInUsers.contains(userName);
    }

    public void removeSession(String userName) {
        loggedInUsers.remove(userName);
    }

    public void removeSession(Authentication authentication) {
        removeSession(userDetailsManager.getUsername(authentication));
    }
}
