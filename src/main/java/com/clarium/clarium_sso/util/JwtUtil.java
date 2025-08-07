package com.clarium.clarium_sso.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

        @Getter
        private Key key;

        @PostConstruct
        public void init() {
            this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        }

    public String generateToken(String email) {
        long EXPIRATION = 1000 * 60 * 60; // 1 hour
        return Jwts.builder()
                    .setSubject(email)
                    .setIssuedAt(Date.from(Instant.now()))
                    .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION))
                    .signWith(key)
                    .compact();
        }

        public String extractEmail(String token) {
            return Jwts.parserBuilder().setSigningKey(key).build()
                    .parseClaimsJws(token).getBody().getSubject();
        }

        public boolean isValid(String token) {
            try {
                Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
                return true;
            } catch (JwtException e) {
                return false;
            }
        }
}
