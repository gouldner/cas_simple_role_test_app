package com.rgps.cas_simple_role_test_app;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class CasAuthenticationUserDetailsService implements AuthenticationUserDetailsService {
    @Override
    public UserDetails loadUserDetails(Authentication authentication) throws UsernameNotFoundException {
        String username = authentication.getName();
        List<GrantedAuthority> authorities = new ArrayList<>();
        return new User(username,"", authorities);
    }

    public User loadUserByUsername(String username) {
        // Entry point for external users
        // Get roles based on username, again for demo just hard coding but you
        // can build based on your own role data store
        List<GrantedAuthority> authorities = new ArrayList<>();

        // I will assume "user" is my in memory user and return EXT_USER role
        // otherwise it must have been a CAS user.
        // More than likely you don't care which method is used to login so
        // you can just add roles based on configuration in your user role store
        // otherwise you need to implement a way to know which type of login was used
        if (username.equals("user")) {
            authorities.add(new SimpleGrantedAuthority("ROLE_EXT_USER"));
        } else {
            authorities.add(new SimpleGrantedAuthority("ROLE_CAS_USER"));
        }

        return new User(username, "", authorities);
    }


}