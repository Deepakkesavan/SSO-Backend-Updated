package com.clarium.clarium_sso.controller;

import com.clarium.clarium_sso.dto.AzureUserAttributes;
import com.clarium.clarium_sso.dto.LoginFailure;
import com.clarium.clarium_sso.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

import static com.clarium.clarium_sso.constant.ApplicationConstants.JWT_TOKEN_TYPE;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/user-attributes")
    public ResponseEntity<AzureUserAttributes> getUserAttributes(){
        return ResponseEntity.ok(authService.getUser());
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(
            HttpServletRequest request,
            HttpServletResponse response) {

        Map<String, Object> result = new HashMap<>();

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            boolean isOAuth2User = authentication != null &&
                    authentication.getPrincipal() instanceof OAuth2User;
            boolean isJwtUser = authentication != null &&
                    authentication.getPrincipal() instanceof String;

            // Handle OAuth2 logout
            if (isOAuth2User && authentication != null) {
                SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
                logoutHandler.setInvalidateHttpSession(true);
                logoutHandler.setClearAuthentication(true);
                logoutHandler.logout(request, response, authentication);
            }

            // Handle JWT logout (clear JWT cookie)
            if (isJwtUser || isOAuth2User) {
                // Clear JWT cookie
                Cookie jwtCookie = new Cookie(JWT_TOKEN_TYPE, "");
                jwtCookie.setPath("/");
                jwtCookie.setMaxAge(0);
                jwtCookie.setHttpOnly(true);
                response.addCookie(jwtCookie);

                // Also try clearing with different path variations
                Cookie jwtCookieRoot = new Cookie(JWT_TOKEN_TYPE, "");
                jwtCookieRoot.setPath("/");
                jwtCookieRoot.setMaxAge(0);
                response.addCookie(jwtCookieRoot);
            }

            // Clear security context
            SecurityContextHolder.clearContext();

            // Clear session if exists
            if (request.getSession(false) != null) {
                request.getSession().invalidate();
            }

            result.put("message", "Logout successful");
            result.put("timestamp", System.currentTimeMillis());
            result.put("userType", isOAuth2User ? "oauth2" : "jwt");

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            // Even if there's an error, try to clear the JWT cookie
            try {
                Cookie jwtCookie = new Cookie(JWT_TOKEN_TYPE, "");
                jwtCookie.setPath("/");
                jwtCookie.setMaxAge(0);
                jwtCookie.setHttpOnly(true);
                response.addCookie(jwtCookie);
                SecurityContextHolder.clearContext();
            } catch (Exception cookieError) {
                // Log but don't fail the logout
            }

            result.put("error", "Logout failed");
            result.put("message", e.getMessage());
            return ResponseEntity.status(500).body(result);
        }
    }

    @GetMapping("/failure")
    public ResponseEntity<LoginFailure> loginFailure() {
        return ResponseEntity.ok(authService.loginFailure());
    }
}