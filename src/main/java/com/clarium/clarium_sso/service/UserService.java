package com.clarium.clarium_sso.service;

import com.clarium.clarium_sso.dto.LoginResponse;
import com.clarium.clarium_sso.exception.EmailAlreadyExistsException;
import com.clarium.clarium_sso.exception.InvalidCredentialsException;
import com.clarium.clarium_sso.exception.NotAnEmployeeException;
import com.clarium.clarium_sso.exception.ResourceNotFoundException;
import com.clarium.clarium_sso.exception.UsernameAlreadyExistsException;
import com.clarium.clarium_sso.model.User;
import com.clarium.clarium_sso.repository.DesignationRepository;
import com.clarium.clarium_sso.repository.EmployeeRepository;
import com.clarium.clarium_sso.repository.UserRepository;
import com.clarium.clarium_sso.repository.WorkInfoRepository;
import com.clarium.clarium_sso.util.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static com.clarium.clarium_sso.constant.ApplicationConstants.*;

@Service
public class UserService {

    private final UserRepository userRepo;
    private final EmployeeRepository employeeRepository;
    private final WorkInfoRepository workInfoRepository;
    private final DesignationRepository designationRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    public UserService(
            JwtUtil jwtUtil,
            AuthenticationManager authenticationManager,
            PasswordEncoder passwordEncoder,
            DesignationRepository designationRepository,
            WorkInfoRepository workInfoRepository,
            UserRepository userRepo,
            EmployeeRepository employeeRepository
    ){
        this.authenticationManager = authenticationManager;
        this.workInfoRepository = workInfoRepository;
        this.userRepo = userRepo;
        this.employeeRepository = employeeRepository;
        this.designationRepository = designationRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    public User register(User user) {
        if (userRepo.existsByEmail(user.getEmail())) {
            throw new EmailAlreadyExistsException(EMAIL_ALREADY_REGISTERED);
        }

        if (userRepo.existsByUsername(user.getUsername())) {
            throw new UsernameAlreadyExistsException(USERNAME_ALREADY_TAKEN);
        }

        if(employeeRepository.existsByEmail(user.getEmail())){
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            return userRepo.save(user);
        }
        else{
            throw new NotAnEmployeeException(EMAIL_NOT_REGISTERED_AS_EMPLOYEE);
        }


    }

    public Integer getEmpIdByEmail(String email) {
        return employeeRepository.findEmpIdByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException(NO_EMPLOYEE_FOUND_WITH_EMAIL + email));
    }

    public String getDesgnIdByEmpId(int empId){
        return workInfoRepository.findDesgnIdByEmpId(empId)
                .orElseThrow(() -> new ResourceNotFoundException(NO_DESIGNATION_ID_FOR_EMPLOYEE_ID + empId));
    }

    public String getDesignationById(String id){
        return designationRepository.findDesignationById(id)
                .orElseThrow(() -> new ResourceNotFoundException(NO_DESIGNATION_FOUND_WITH_ID + id));
    }


    public LoginResponse loginWithJwt(String email, String rawPassword, HttpServletResponse response) {
        try {
            // Use Spring Security's authentication manager
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, rawPassword)
            );

            User user = userRepo.findByEmail(email)
                    .orElseThrow(() -> new ResourceNotFoundException(USER_NOT_FOUND_WITH_EMAIL_ID + email));

            String token = jwtUtil.generateToken(user.getEmail());

            ResponseCookie jwtCookie = ResponseCookie.from(JWT_TOKEN_TYPE, token)
                    .httpOnly(true)
                    .secure(false)
                    .path("/")
                    .maxAge(60 * 60 * 2)
                    .build();

            response.addHeader(HttpHeaders.SET_COOKIE, jwtCookie.toString());

            int empId = getEmpIdByEmail(user.getEmail());
            String desgnId = getDesgnIdByEmpId(empId);
            String designation = getDesignationById(desgnId);

            return new LoginResponse(
                    LOGIN_SUCCESSFUL,
                    empId,
                    designation
            );
        }
        catch (Exception e) {
            throw new InvalidCredentialsException(INVALID_EMAIL_OR_PASSWORD);
        }
    }



}