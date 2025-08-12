package com.clarium.clarium_sso.service;

import com.clarium.clarium_sso.dto.AzureUserAttributes;
import com.clarium.clarium_sso.dto.LoginFailure;
import com.clarium.clarium_sso.dto.UserAttributes;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import static com.clarium.clarium_sso.constant.ApplicationConstants.*;

@Service
public class AuthService {


    private final UserService userService;

    public AuthService(UserService userService) {
        this.userService = userService;
    }

    public AzureUserAttributes getUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.isAuthenticated() && auth.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauthUser = (OAuth2User) auth.getPrincipal();

            UserAttributes userAttributes = new UserAttributes(
                    oauthUser.getAttribute(OAUTH_ATTR_GIVEN_NAME),
                    oauthUser.getAttribute(OAUTH_ATTR_FAMILY_NAME),
                    oauthUser.getAttribute(OAUTH_ATTR_NAME),
                    oauthUser.getAttribute(OAUTH_ATTR_SUB),
                    oauthUser.getAttribute(OAUTH_ATTR_EMAIL),
                    oauthUser.getAttribute(OAUTH_ATTR_PICTURE)
            );
//            int empId = userService.getEmpIdByEmail(oauthUser.getAttribute(OAUTH_ATTR_EMAIL));
//            String desgnId = userService.getDesgnIdByEmpId(empId);
//            String designation = userService.getDesignationById(desgnId);
            return new AzureUserAttributes(true, 0, null, userAttributes);
        } else {
            return new AzureUserAttributes(false, 0, null, null);
        }
    }

    public LoginFailure loginFailure(){
        return new LoginFailure(false, AUTHENTICATION_FAILED);
    }

}
