package com.clarium.clarium_sso.security;

import com.clarium.clarium_sso.util.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.util.List;

import java.io.IOException;

import static com.clarium.clarium_sso.constant.ApplicationConstants.*;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String token = null;

        // *** Try to extract from Authorization header
//        String authHeader = request.getHeader(AUTHORIZATION_HEADER);
//        if (authHeader != null && authHeader.startsWith(TOKEN_PREFIX)) {
//            token = authHeader.substring(7);
//        }

        //try to extract from cookie
        if (request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                if (cookie.getName().equals(JWT_TOKEN_TYPE)) {
                    token = cookie.getValue();
                    break;
                }
            }
        }

        //validate and handle expired token
        if (token != null) {
            try {
                // Token valid
                if (jwtUtil.isValid(token)) {
                    String email = jwtUtil.extractEmail(token);
                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(
                                    email, null, List.of(new SimpleGrantedAuthority(ROLE_USER)));

                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            } catch (ExpiredJwtException e) {
                try {
                    String email = e.getClaims().getSubject();
                    String newToken = jwtUtil.generateToken(email);

                    ResponseCookie refreshedCookie = ResponseCookie.from(JWT_TOKEN_TYPE, newToken)
                            .httpOnly(true)
                            .secure(false)
                            .path("/")
                            .maxAge(60 * 60 * 2)
                            .build();

                    response.addHeader(HttpHeaders.SET_COOKIE, refreshedCookie.toString());

                    // Update auth context
                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(
                                    email, null, List.of(new SimpleGrantedAuthority(ROLE_USER)));

                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(auth);

                } catch (Exception ex) {
                    SecurityContextHolder.clearContext();
                }
            }
        }

        filterChain.doFilter(request, response);
    }

}