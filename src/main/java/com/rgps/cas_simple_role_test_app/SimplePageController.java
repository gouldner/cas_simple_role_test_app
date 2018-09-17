package com.rgps.cas_simple_role_test_app;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SimplePageController {

    @RequestMapping("/notprotected")
    public String HelloAgain() {
        return "Hello from a non-protected page";
    }

    @RequestMapping("/denyAll")
    public String denyAll() {
        return "Hello you really shouldn't be here.";
    }


    @RequestMapping("/externalUser")
    public String HelloExternalUser() {
        return "Hello External User with User Role";
    }

    @Secured("ROLE_USER")
    @RequestMapping("/protectedByUserRole")
    public String HelloUser() {
        return "Hello User Role";
    }

    @Secured("ROLE_ADMIN")
    @RequestMapping("/protectedByAdminRole")
    public String HelloAdmin() {
        return "Hello Admin Role";
    }

    @Secured("ROLE_COIADMIN")
    @RequestMapping("/protectedByCoiAdminRole")
    public String HelloCoiAdmin() {
        return "Hello Coi Admin Role";
    }
}
