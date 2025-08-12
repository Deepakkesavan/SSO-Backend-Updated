package com.clarium.clarium_sso.controller;

import com.clarium.clarium_sso.dto.AzureUserAttributes;
import com.clarium.clarium_sso.dto.LoginFailure;
import com.clarium.clarium_sso.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

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

            if (authentication != null) {
                // Use Spring Security's logout handler
                SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
                logoutHandler.setInvalidateHttpSession(true);
                logoutHandler.setClearAuthentication(true);
                logoutHandler.logout(request, response, authentication);
            }

            // Clear security context
            SecurityContextHolder.clearContext();

            result.put("message", "Logout successful");
            result.put("timestamp", System.currentTimeMillis());
            return ResponseEntity.ok(result);

        } catch (Exception e) {
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
