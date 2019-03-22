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

    @Secured("ROLE_CAS_USER")
    @RequestMapping("/protectedByCasUserRole")
    public String HelloCasUserUser() {
        return "Hello Cas Authenticated User";
    }

    @Secured("ROLE_EXT_USER")
    @RequestMapping("/protectedByExtUserRole")
    public String HelloExternalUser() {
        return "Hello External Authenticated User";
    }
}
