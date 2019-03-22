package com.rgps.cas_simple_role_test_app;

import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import org.thymeleaf.extras.springsecurity4.dialect.SpringSecurityDialect;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Value("${application_base_url}")
    String applicationBaseUrl;

    @Value("${casBaseUrl}")
    String casBaseUrl;

    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService("http://localhost:8099/j_spring_cas_security_check");
        serviceProperties.setSendRenew(false);
        return serviceProperties;
    }

    public AuthenticationUserDetailsService authenticationUserDetailsService() {
        return new CasAuthenticationUserDetailsService();
    }

    @Bean
    public Cas20ServiceTicketValidator cas20ServiceTicketValidator() {
        return new Cas20ServiceTicketValidator("https://kcdev.ors.hawaii.edu/cas");
    }

    @Bean
    public CasAuthenticationFilter casAuthenticationFilter() throws Exception {
        CasAuthenticationFilter casAuthenticationFilter = new CasAuthenticationFilter();
        casAuthenticationFilter.setAuthenticationManager(authenticationManager());
        return casAuthenticationFilter;
    }

    @Bean
    public CasAuthenticationEntryPoint casAuthenticationEntryPoint() {
        CasAuthenticationEntryPoint casAuthenticationEntryPoint = new CasAuthenticationEntryPoint();
        casAuthenticationEntryPoint.setLoginUrl(casBaseUrl + "/login");
        casAuthenticationEntryPoint.setServiceProperties(serviceProperties());
        return casAuthenticationEntryPoint;
    }

    @Bean
    public JwtCookieRequestCache requestCache(@Value("${authentication.jwt.token.secret}") String secret) {
        return new JwtCookieRequestCache(secret);
    }


    @Bean
    public JWTSecurityContextRepository contextRepository(CasAuthenticationUserDetailsService detailsManager,
                                                          @Value("${authentication.jwt.token.name}") String tokenName,
                                                          @Value("${authentication.jwt.token.secret}") String secret) {
        return new JWTSecurityContextRepository(detailsManager, tokenName, secret);
    }


    @Bean
    public CasAuthenticationProvider casAuthenticationProvider() {
        CasAuthenticationProvider casAuthenticationProvider = new CasAuthenticationProvider();
        casAuthenticationProvider.setAuthenticationUserDetailsService(authenticationUserDetailsService());
        casAuthenticationProvider.setServiceProperties(serviceProperties());
        casAuthenticationProvider.setTicketValidator(cas20ServiceTicketValidator());
        casAuthenticationProvider.setKey(applicationBaseUrl);
        return casAuthenticationProvider;
    }

    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler authenticationSuccessHandler(RequestCache cache) {
        SavedRequestAwareAuthenticationSuccessHandler requestAwareAuthenticationSuccessHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        requestAwareAuthenticationSuccessHandler.setRequestCache(cache);
        return requestAwareAuthenticationSuccessHandler;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        JwtCookieRequestCache jwtCookieRequestCache = getApplicationContext().getBean(JwtCookieRequestCache.class);
        JWTSecurityContextRepository securityContextRepository = getApplicationContext().getBean(JWTSecurityContextRepository.class);
        AuthenticationSuccessHandler successHandler = getApplicationContext().getBean(AuthenticationSuccessHandler.class);

        http
                .requestCache().requestCache(jwtCookieRequestCache)
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .securityContext().securityContextRepository(securityContextRepository)
                .and()
                .addFilter(casAuthenticationFilter())
                .addFilterBefore(logoutFilter(), LogoutFilter.class)
                .addFilterBefore(singleSignOutFilter(), CasAuthenticationFilter.class)
                .exceptionHandling()
                .authenticationEntryPoint(casAuthenticationEntryPoint())
                .and()
                .formLogin()
                .successHandler(successHandler)
                .loginPage("/external_login") // If user requests this page let them login as external user
                .permitAll()
                .and()
                .authorizeRequests() // Otherwise use CAS authentication
                .antMatchers("/protectedByUserRole*").hasRole("USER")
                .antMatchers("/protectedByAdminRole*").hasRole("ADMIN")
                .antMatchers("/protectedByCOIAdminRole*").hasRole("COIADMIN")
                .antMatchers("/","/notprotected*").permitAll()
                .antMatchers("/denyAll*").denyAll()
                .antMatchers("/").permitAll() // This allows non-authenticated users to reach front page and choose login option
                .anyRequest().authenticated()
                .and()
                .httpBasic();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Add CAS authentications
        auth.authenticationProvider(casAuthenticationProvider());

        // Add JDBC db authentication for external users (more likely approach but you need to autowire you database dataSource)
        //auth.jdbcAuthentication().dataSource(dataSource).passwordEncoder(new BCryptPasswordEncoder())
        //        .usersByUsernameQuery(
        //                "select username,password, enabled from users where username=?")
        //        .authoritiesByUsernameQuery("select username, authority from authorities where username=?");

        // Add in memory user auth for easy to implement example.
        auth.inMemoryAuthentication()
                .withUser("user")
                .password("{noop}password")
                .roles("EXT_USER");
    }

    // Thymeleaf Security configuration for <div sec:authorize="#{isAuthenticated()}"> etc
    @Bean
    public SpringSecurityDialect springSecurityDialect(){
        return new SpringSecurityDialect();
    }

    public SecurityContextLogoutHandler securityContextLogoutHandler() {
        SecurityContextLogoutHandler securityContextLogoutHandler = new SecurityContextLogoutHandler();
        return securityContextLogoutHandler;
    }

    public LogoutFilter logoutFilter() {
        String logouturl=casBaseUrl+"/logout?service=" + applicationBaseUrl;
        LogoutFilter logoutFilter = new LogoutFilter(logouturl,
                securityContextLogoutHandler());
        return logoutFilter;
    }

    private SingleSignOutFilter singleSignOutFilter() {
        SingleSignOutFilter filter = new SingleSignOutFilter();
        return filter;
    }
}
