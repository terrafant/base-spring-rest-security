package com.uay.security.service;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class SecurityContextService {

    public SecurityContext constructSecurityContext(UserDetails userDetails) {
        if (userDetails != null) {
            SecurityContextImpl securityContext = new SecurityContextImpl();
            Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
            securityContext.setAuthentication(authentication);
            return securityContext;
        }
        return SecurityContextHolder.createEmptyContext();
    }
}
