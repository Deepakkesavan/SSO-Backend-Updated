package com.clarium.clarium_sso.service;

import com.clarium.clarium_sso.dto.AzureUserAttributes;
import com.clarium.clarium_sso.dto.LoginFailure;
import com.clarium.clarium_sso.dto.UserAttributes;
import com.clarium.clarium_sso.model.User;
import com.clarium.clarium_sso.repository.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import static com.clarium.clarium_sso.constant.ApplicationConstants.*;

@Service
public class AuthService {

    private final UserService userService;
    private final UserRepository userRepository;

    public AuthService(UserService userService, UserRepository userRepository) {
        this.userService = userService;
        this.userRepository = userRepository;
    }

    public AzureUserAttributes getUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.isAuthenticated()) {
            // Handle OAuth2 authentication
            if (auth.getPrincipal() instanceof OAuth2User) {
                OAuth2User oauthUser = (OAuth2User) auth.getPrincipal();

                UserAttributes userAttributes = new UserAttributes(
                        oauthUser.getAttribute(OAUTH_ATTR_GIVEN_NAME),
                        oauthUser.getAttribute(OAUTH_ATTR_FAMILY_NAME),
                        oauthUser.getAttribute(OAUTH_ATTR_NAME),
                        oauthUser.getAttribute(OAUTH_ATTR_SUB),
                        oauthUser.getAttribute(OAUTH_ATTR_EMAIL),
                        oauthUser.getAttribute(OAUTH_ATTR_PICTURE)
                );

                try {
//                    int empId = userService.getEmpIdByEmail(oauthUser.getAttribute(OAUTH_ATTR_EMAIL));
//                    String desgnId = userService.getDesgnIdByEmpId(empId);
//                    String designation = userService.getDesignationById(desgnId);
                    return new AzureUserAttributes(true, 0, null, userAttributes);
                } catch (Exception e) {
                    // If employee info not found, still return authenticated user
                    return new AzureUserAttributes(true, 0, null, userAttributes);
                }
            }
            // Handle JWT authentication (custom login)
            else if (auth.getPrincipal() instanceof String) {
                String email = (String) auth.getPrincipal();

                // Get user from database
                User user = userRepository.findByEmail(email).orElse(null);
                if (user != null) {
                    UserAttributes userAttributes = new UserAttributes(
                            null, // given name not available for custom users
                            null, // family name not available
                            user.getUsername(),
                            user.getId().toString(),
                            user.getEmail(),
                            null // picture not available
                    );

                    try {
//                        int empId = userService.getEmpIdByEmail(user.getEmail());
//                        String desgnId = userService.getDesgnIdByEmpId(empId);
//                        String designation = userService.getDesignationById(desgnId);
                        return new AzureUserAttributes(true, 0, null, userAttributes);
                    } catch (Exception e) {
                        // If employee info not found, still return authenticated user
                        return new AzureUserAttributes(true, 0, "Unknown", userAttributes);
                    }
                }
            }
        }

        return new AzureUserAttributes(false, 0, null, null);
    }

    public LoginFailure loginFailure(){
        return new LoginFailure(false, AUTHENTICATION_FAILED);
    }
}