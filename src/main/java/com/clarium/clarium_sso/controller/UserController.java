package com.clarium.clarium_sso.controller;

import com.clarium.clarium_sso.dto.LoginRequest;
import com.clarium.clarium_sso.dto.LoginResponse;
import com.clarium.clarium_sso.dto.SignupResponse;
import com.clarium.clarium_sso.model.User;
import com.clarium.clarium_sso.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static com.clarium.clarium_sso.constant.ApplicationConstants.*;

@RestController
@RequestMapping("/custom-login/auth")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/test")
    public String test() {
        return TEST_ENDPOINT_SUCCESS;
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getProfile() {
        return ResponseEntity.ok(PROTECTED_ROUTE_ACCESS);
    }

    @PostMapping("testing")
    public String testing(@RequestParam String name)
    {
        return name;
    }


    @PostMapping("/signup")
    public ResponseEntity<SignupResponse> register(@RequestBody User user) {
        User savedUser = userService.register(user);
        SignupResponse signupResponse = new SignupResponse(SIGNUP_SUCCESSFUL, savedUser.getEmail());
        return ResponseEntity.status(HttpStatus.CREATED).body(signupResponse);

    }

    @PostMapping("/signin")
    public ResponseEntity<?> login(@RequestBody LoginRequest req, HttpServletResponse response) {
        LoginResponse Loginresponse = userService.loginWithJwt(req.email(), req.password(), response);
        return ResponseEntity.ok(Loginresponse);

    }
}