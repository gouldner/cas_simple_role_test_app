package com.rgps.cas_simple_role_test_app;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SaveContextOnUpdateOrErrorResponseWrapper;
import org.springframework.security.web.context.SecurityContextRepository;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;

/**
 * Created by Daniel Wasilew on 30.11.17
 * (c) 2017 Daniel Wasilew <daniel@dedicatedcode.com>
 */
public class JWTSecurityContextRepository implements SecurityContextRepository {
    private static final Logger log = LoggerFactory.getLogger(JWTSecurityContextRepository.class);

    private final CasAuthenticationUserDetailsService userDetailsManager;
    private final String tokenName;
    private final String secret;

    JWTSecurityContextRepository(CasAuthenticationUserDetailsService userDetailsManager, String tokenName, String secret) {
        this.userDetailsManager = userDetailsManager;
        this.tokenName = tokenName;
        this.secret = secret;
    }

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest request = requestResponseHolder.getRequest();
        HttpServletResponse response = requestResponseHolder.getResponse();
        requestResponseHolder.setResponse(new SaveToCookieResponseWrapper(request, response, tokenName, secret));
        SecurityContext context = readSecurityContextFromCookie(request);
        if (context == null) {
            return SecurityContextHolder.createEmptyContext();
        }
        return context;
    }

    private SecurityContext readSecurityContextFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        } else {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(tokenName)) {
                    try {
                        String username = Jwts.parser().setSigningKey(secret).parse(cookie.getValue(), new JwtHandlerAdapter<String>() {
                            @Override
                            public String onClaimsJws(Jws<Claims> jws) {
                                return jws.getBody().getSubject();
                            }
                        });
                        SecurityContext context = SecurityContextHolder.createEmptyContext();
                        UserDetails userDetails = this.userDetailsManager.loadUserByUsername(username);
                        context.setAuthentication(new UsernamePasswordAuthenticationToken(userDetails.getUsername(), userDetails.getPassword(), userDetails.getAuthorities()));
                        return context;
                    } catch (ExpiredJwtException ex) {
                        log.debug("authentication cookie is expired");
                    } catch (UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
                        log.warn("tampered jwt authentication cookie detected");
                        return null;
                    }
                    System.out.println();
                }
            }
        }
        //log.debug("no [{}] found in request.", tokenName);
        return null;
    }


    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        SaveToCookieResponseWrapper responseWrapper = (SaveToCookieResponseWrapper) response;
        if (!responseWrapper.isContextSaved()) {
            responseWrapper.saveContext(context);
        }

    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return readSecurityContextFromCookie(request) != null;
    }


    private static class SaveToCookieResponseWrapper extends SaveContextOnUpdateOrErrorResponseWrapper {

        private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

        private final HttpServletRequest request;
        private final String token;
        private final String secret;

        SaveToCookieResponseWrapper(HttpServletRequest request, HttpServletResponse response, String token, String secret) {
            super(response, true);
            this.request = request;
            this.token = token;
            this.secret = secret;
        }

        @Override
        protected void saveContext(SecurityContext securityContext) {
            HttpServletResponse response = (HttpServletResponse) getResponse();
            Authentication authentication = securityContext.getAuthentication();
            if (authentication == null || trustResolver.isAnonymous(authentication)) {
                response.addCookie(createExpireAuthenticationCookie(request));
                return;
            }
            Date expiresAt = new Date(System.currentTimeMillis() + 3600000);
            String jwt = Jwts.builder()
                    .signWith(SignatureAlgorithm.HS512, secret)
                    .setSubject(authentication.getName())
                    .setExpiration(expiresAt).compact();
            response.addCookie(createAuthenticationCookie(jwt));
        }

        private Cookie createAuthenticationCookie(String cookieValue) {
            Cookie authenticationCookie = new Cookie(token, cookieValue);
            authenticationCookie.setPath("/");
            authenticationCookie.setHttpOnly(true);
            authenticationCookie.setSecure(request.isSecure());
            authenticationCookie.setMaxAge(3600000);
            return authenticationCookie;
        }

        private Cookie createExpireAuthenticationCookie(HttpServletRequest request) {
            Cookie removeSessionCookie = new Cookie(token, "");
            removeSessionCookie.setPath("/");
            removeSessionCookie.setMaxAge(0);
            removeSessionCookie.setHttpOnly(true);
            removeSessionCookie.setSecure(request.isSecure());
            return removeSessionCookie;
        }

    }
}

