package com.example.demo.security;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import com.auth0.jwt.JWT;

@Component
public class JWTAuthenticationFilterVeification extends BasicAuthenticationFilter {

    public JWTAuthenticationFilterVeification(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String header = request.getHeader(SecurityConstant.HEADER_STRING);
        if (ObjectUtils.isEmpty(header) || !header.startsWith(SecurityConstant.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken user = this.getAuthentication(request);
        SecurityContextHolder.getContext().setAuthentication(user);
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest req) {
        String token = req.getHeader(SecurityConstant.HEADER_STRING);
        if (!ObjectUtils.isEmpty(token)) {
            String user = JWT.require(HMAC512(SecurityConstant.SECRET_KEY.getBytes())).build()
                    .verify(token.replace(SecurityConstant.TOKEN_PREFIX, "")).getSubject();
            if (!ObjectUtils.isEmpty(user)) {
                return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
            }
            return null;
        }
        return null;
    }

}
