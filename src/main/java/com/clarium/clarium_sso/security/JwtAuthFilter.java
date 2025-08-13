package com.clarium.clarium_sso.security;

import com.clarium.clarium_sso.util.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

        // Skip JWT processing for OAuth2 endpoints and public endpoints
        String requestURI = request.getRequestURI();
        if (requestURI.startsWith("/oauth2/") ||
                requestURI.startsWith("/login/") ||
                requestURI.equals("/custom-login/auth/signin") ||
                requestURI.equals("/custom-login/auth/signup")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract JWT token from cookie
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (JWT_TOKEN_TYPE.equals(cookie.getName())) {
                    token = cookie.getValue();
                    break;
                }
            }
        }

        // Process JWT token if present
        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
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
                    // Try to refresh the token
                    String email = e.getClaims().getSubject();
                    String newToken = jwtUtil.generateToken(email);

                    // Set new token in cookie
                    Cookie refreshedCookie = new Cookie(JWT_TOKEN_TYPE, newToken);
                    refreshedCookie.setHttpOnly(true);
                    refreshedCookie.setSecure(false); // Set to true in production with HTTPS
                    refreshedCookie.setPath("/");
                    refreshedCookie.setMaxAge(60 * 60 * 2); // 2 hours
                    response.addCookie(refreshedCookie);

                    // Update auth context
                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(
                                    email, null, List.of(new SimpleGrantedAuthority(ROLE_USER)));

                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(auth);

                } catch (Exception ex) {
                    // Clear the invalid token
                    Cookie clearCookie = new Cookie(JWT_TOKEN_TYPE, "");
                    clearCookie.setPath("/");
                    clearCookie.setMaxAge(0);
                    response.addCookie(clearCookie);
                    SecurityContextHolder.clearContext();
                }
            } catch (Exception e) {
                // Invalid token - clear it
                Cookie clearCookie = new Cookie(JWT_TOKEN_TYPE, "");
                clearCookie.setPath("/");
                clearCookie.setMaxAge(0);
                response.addCookie(clearCookie);
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }
}