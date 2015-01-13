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

    public String getUsername(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() != null) {
            return ((UserDetails)authentication.getPrincipal()).getUsername();
        }
        return null;
    }
}
