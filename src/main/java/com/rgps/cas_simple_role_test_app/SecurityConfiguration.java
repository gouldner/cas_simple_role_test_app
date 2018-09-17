package com.rgps.cas_simple_role_test_app;

import com.kakawait.spring.boot.security.cas.CasSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
// Replace CasSecurityConfigurerAdapter with WebSecurityConfigurerAdapter to see this code working fine.
public class SecurityConfiguration extends CasSecurityConfigurerAdapter {
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/protectedByUserRole*").hasRole("USER")
                .antMatchers("/protectedByAdminRole*").hasRole("ADMIN")
                .antMatchers("/protectedByCOIAdminRole*").hasRole("COIADMIN")
                .antMatchers("/","/notprotected*").permitAll()
                .antMatchers("/","/denyAll*").denyAll()
                .and()
                .httpBasic();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder authenticationMgr) throws Exception {
        authenticationMgr.inMemoryAuthentication()
                .withUser("devuser").password("{noop}dev").authorities("ROLE_USER")
                .and()
                .withUser("adminuser").password("{noop}admin").authorities("ROLE_USER","ROLE_ADMIN")
                .and()
                .withUser("coiadminuser").password("{noop}admin").authorities("ROLE_USER","ROLE_COIADMIN");;
    }
}
