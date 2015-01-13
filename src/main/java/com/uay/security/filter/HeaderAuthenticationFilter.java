package com.uay.security.filter;

import com.uay.security.service.SecurityContextService;
import com.uay.security.service.UserDetailsManager;
import com.uay.security.util.HeaderUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class HeaderAuthenticationFilter extends GenericFilterBean {

    @Autowired
    private HeaderUtil headerUtil;
    @Autowired
    private UserDetailsManager userDetailsManager;
    @Autowired
    private SecurityContextService securityContextService;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        UserDetails userDetails = userDetailsManager.loadUserDetails((HttpServletRequest) request);
        SecurityContext contextBeforeChainExecution = securityContextService.constructSecurityContext(userDetails);

        try {
            SecurityContextHolder.setContext(contextBeforeChainExecution);
            if (contextBeforeChainExecution.getAuthentication() != null && contextBeforeChainExecution.getAuthentication().isAuthenticated()) {
                String userName = userDetailsManager.getUsername(contextBeforeChainExecution.getAuthentication());
                headerUtil.addHeader((HttpServletResponse) response, userName);
            }
            filterChain.doFilter(request, response);
        }
        finally {
            // Clear the context and free the threadlocal
            SecurityContextHolder.clearContext();
        }
    }
}
