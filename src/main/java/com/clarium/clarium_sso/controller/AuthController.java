package com.clarium.clarium_sso.controller;

import com.clarium.clarium_sso.dto.AzureUserAttributes;
import com.clarium.clarium_sso.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
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

    @GetMapping("/failure")
    public ResponseEntity<Map<String, Object>> loginFailure() {
        return ResponseEntity.ok(authService.loginFailure());
    }

}
