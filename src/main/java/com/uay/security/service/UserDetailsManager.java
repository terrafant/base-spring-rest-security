package com.uay.security.service;

import com.uay.security.util.HeaderUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

@Service
public class UserDetailsManager {

    @Autowired
    @Qualifier("inMemoryUserDetailsService")
    private UserDetailsService userDetailsService;

    @Autowired
    private HeaderUtil headerUtil;

    @Autowired
    private SessionManager sessionManager;

    public UserDetails loadUserDetails(HttpServletRequest request) {
        String userName = headerUtil.getUserName(request);

        return userName != null && sessionManager.hasLoggedIn(userName)
                ? userDetailsService.loadUserByUsername(userName)
                : null;
    }

    public String retrieveUsername(Authentication authentication) {
        if (isInstanceOfUserDetails(authentication)) {
            return ((UserDetails) authentication.getPrincipal()).getUsername();
        }
        else {
            return authentication.getPrincipal().toString();
        }
    }

    public String retrievePassword(Authentication authentication) {
        if (isInstanceOfUserDetails(authentication)) {
            return ((UserDetails) authentication.getPrincipal()).getPassword();
        }
        else {
            if (authentication.getCredentials() == null) {
                return null;
            }
            return authentication.getCredentials().toString();
        }
    }

    private boolean isInstanceOfUserDetails(Authentication authentication) {
        return authentication.getPrincipal() instanceof UserDetails;
    }

}
