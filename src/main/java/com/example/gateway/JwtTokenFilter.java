package com.example.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    private static final Logger LOG = LoggerFactory.getLogger(JwtTokenFilter.class);

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    private String token;

    private static final String AUTHORIZATION = "Authorization";

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse rsp, FilterChain filterChain) throws ServletException, IOException {
        token = req.getHeader(AUTHORIZATION);
        if (token != null && token.startsWith("Bearer" + " ")) {
            token = token.replace("Bearer" + " ", "");
            try {
                String username = jwtTokenUtil.getUsernameFromToken(token);
                if (username != null) {
                    UsernamePasswordAuthenticationToken authentication = jwtTokenUtil.getAuthenticationToken(token, SecurityContextHolder.getContext().getAuthentication(), username);
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
                    logger.info("authenticated user " + username + ", setting security context");
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    filterChain.doFilter(req, rsp);
                } else {
                    if (req.getRequestURI().equals("/api/authenticate/logout")) {
                        rsp.setHeader(AUTHORIZATION, req.getHeader(AUTHORIZATION));
                        filterChain.doFilter(req, rsp);
                    } else {
                        rsp.sendError(400, "Your account is deactivate");
                    }
                }
            } catch (Exception ignore) {
                SecurityContextHolder.clearContext();
            }
        } else {
            filterChain.doFilter(req, rsp);
        }

    }
}
