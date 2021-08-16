package com.example.gateway;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    @Value("${const.security.jwt.secret}")
    private String secret;
    private static final Logger LOG = LoggerFactory.getLogger(JwtTokenFilter.class);


    private String token;

    private static final String AUTHORIZATION = "Authorization";

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse rsp, FilterChain filterChain) throws ServletException, IOException {
        token = req.getHeader(AUTHORIZATION);
        if (token != null && token.startsWith("Bearer" + " ")) {
            token = token.replace("Bearer" + " ", "");
            try {
                LOG.info("Session filter {}", req.getHeader(AUTHORIZATION));
                Claims claims = Jwts.parser()
                        .setSigningKey(secret)
                        .parseClaimsJws(token)
                        .getBody();
                String username = claims.getSubject();

                List<String> authorities = claims.get("authorities", List.class);
                String auth1 = "";
                for (String authority : authorities) {
                    auth1 = authority;
                }
                if (username != null) {
                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null,
                            authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
                    SecurityContextHolder.getContext().setAuthentication(auth);
                    filterChain.doFilter(req, rsp);
                } else {
                    System.out.println(req.getRequestURI());
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
