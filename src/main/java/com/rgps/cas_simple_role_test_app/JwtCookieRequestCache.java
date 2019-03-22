package com.rgps.cas_simple_role_test_app;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.compression.GzipCompressionCodec;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.savedrequest.*;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Created by Daniel Wasilew on 10.12.17
 * (c) 2017 Daniel Wasilew <daniel@dedicatedcode.com>
 */
public class JwtCookieRequestCache implements RequestCache {
    private static final Logger log = LoggerFactory.getLogger(JwtCookieRequestCache.class);
    private static final String NAME = "saved_request";
    private final String secret;
    private PortResolver portResolver = new PortResolverImpl();
    private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;

    private static final Gson GSON = new GsonBuilder().create();

    public JwtCookieRequestCache(String secret) {
        this.secret = secret;
    }

    @Override
    public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
        if (requestMatcher.matches(request)) {
            DefaultSavedRequest base = new DefaultSavedRequest(request,
                    portResolver);

            Map<String, List<String>> header = new HashMap<>();
            base.getHeaderNames().forEach(x -> header.put(x, base.getHeaderValues(x)));

            DefaultSavedRequest savedRequest = new DefaultSavedRequest.Builder()
                    .setRequestURI(base.getRequestURI())
                    .setRequestURL(base.getRequestURL())
                    .setHeaders(header)
                    .setContextPath(base.getContextPath())
                    .setCookies(base.getCookies().stream().filter(c -> !c.getName().equalsIgnoreCase("saved_request")).map(SavedCookie::new).collect(Collectors.toList()))
                    .setLocales(base.getLocales())
                    .setMethod(base.getMethod())
                    .setParameters(base.getParameterMap())
                    .setPathInfo(base.getPathInfo())
                    .setQueryString(base.getQueryString())
                    .setScheme(base.getScheme())
                    .setServerName(base.getServerName())
                    .setServerPort(base.getServerPort())
                    .setServletPath(base.getServletPath())
                    .build();


            String compact = Jwts.builder().signWith(SignatureAlgorithm.HS512, secret).compressWith(new GzipCompressionCodec()).setSubject(GSON.toJson(savedRequest)).compact();
            addCookie(request, response, compact, -1);
        }
    }

    @Override
    public SavedRequest getRequest(HttpServletRequest request, HttpServletResponse response) {
        return loadFromCookie(request);
    }

    private SavedRequest loadFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            log.trace("no cookies found");
            return null;
        } else {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(NAME) && !cookie.getValue().isEmpty()) {
                    SavedRequest savedRequest = null;
                    try {
                        savedRequest = Jwts.parser().setSigningKey(secret).parse(cookie.getValue(), new JwtHandlerAdapter<SavedRequest>() {
                            @Override
                            public SavedRequest onClaimsJws(Jws<Claims> jws) {
                                return GSON.fromJson(jws.getBody().getSubject(), DefaultSavedRequest.class);
                            }
                        });
                    } catch (ExpiredJwtException | UnsupportedJwtException | SignatureException | MalformedJwtException | IllegalArgumentException e) {
                        log.warn("cant process jwt saved request", e);
                    }
                    log.trace("saved request [{}] found", savedRequest);
                    return savedRequest;
                }
            }
        }
        log.trace("no cookie for [{}] found", NAME);
        return null;
    }

    @Override
    public HttpServletRequest getMatchingRequest(HttpServletRequest request, HttpServletResponse response) {
        DefaultSavedRequest saved = (DefaultSavedRequest) getRequest(request, response);

        if (saved == null) {
            log.trace("no saved request found");
            return null;
        }
        if (!saved.doesRequestMatch(request, portResolver)) {
            log.trace("saved request does not match");
            return null;
        }

        removeRequest(request, response);
        return new SavedRequestAwareWrapper(saved, request);
    }


    private void addCookie(HttpServletRequest request, HttpServletResponse response, String value, int expiry) {
        Cookie cookie = new Cookie(NAME, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(request.isSecure());
        cookie.setPath("/");
        cookie.setMaxAge(expiry);
        response.addCookie(cookie);
    }

    @Override
    public void removeRequest(HttpServletRequest request, HttpServletResponse response) {
        addCookie(request, response, "", 0);
        log.trace("deleting saved request cookie");
    }

    private static class SavedRequestAwareWrapper extends HttpServletRequestWrapper {
        // ~ Static fields/initializers
        // =====================================================================================

        protected static final Log logger = LogFactory.getLog(SavedRequestAwareWrapper.class);
        static final TimeZone GMT_ZONE = TimeZone.getTimeZone("GMT");

        // ~ Instance fields
        // ================================================================================================

        SavedRequest savedRequest = null;

        /**
         * The set of SimpleDateFormat formats to use in getDateHeader(). Notice that because
         * SimpleDateFormat is not thread-safe, we can't declare formats[] as a static
         * variable.
         */
        protected final SimpleDateFormat[] formats = new SimpleDateFormat[3];

        // ~ Constructors
        // ===================================================================================================

        SavedRequestAwareWrapper(SavedRequest saved, HttpServletRequest request) {
            super(request);
            savedRequest = saved;

            formats[0] = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
            formats[1] = new SimpleDateFormat("EEEEEE, dd-MMM-yy HH:mm:ss zzz", Locale.US);
            formats[2] = new SimpleDateFormat("EEE MMMM d HH:mm:ss yyyy", Locale.US);

            formats[0].setTimeZone(GMT_ZONE);
            formats[1].setTimeZone(GMT_ZONE);
            formats[2].setTimeZone(GMT_ZONE);
        }

        // ~ Methods
        // ========================================================================================================

        @Override
        public long getDateHeader(String name) {
            String value = getHeader(name);

            if (value == null) {
                return -1L;
            }

            // Attempt to convert the date header in a variety of formats
            long result = FastHttpDateFormat.parseDate(value, formats);

            if (result != -1L) {
                return result;
            }

            throw new IllegalArgumentException(value);
        }

        @Override
        public String getHeader(String name) {
            List<String> values = savedRequest.getHeaderValues(name);

            return values.isEmpty() ? null : values.get(0);
        }

        @Override
        @SuppressWarnings("unchecked")
        public Enumeration getHeaderNames() {
            return new Enumerator<>(savedRequest.getHeaderNames());
        }

        @Override
        @SuppressWarnings("unchecked")
        public Enumeration getHeaders(String name) {
            return new Enumerator<>(savedRequest.getHeaderValues(name));
        }

        @Override
        public int getIntHeader(String name) {
            String value = getHeader(name);

            if (value == null) {
                return -1;
            } else {
                return Integer.parseInt(value);
            }
        }

        @Override
        public Locale getLocale() {
            List<Locale> locales = savedRequest.getLocales();

            return locales.isEmpty() ? Locale.getDefault() : locales.get(0);
        }

        @Override
        @SuppressWarnings("unchecked")
        public Enumeration getLocales() {
            List<Locale> locales = savedRequest.getLocales();

            if (locales.isEmpty()) {
                // Fall back to default locale
                locales = new ArrayList<>(1);
                locales.add(Locale.getDefault());
            }

            return new Enumerator<>(locales);
        }

        @Override
        public String getMethod() {
            return savedRequest.getMethod();
        }

        /**
         * If the parameter is available from the wrapped request then the request has been
         * forwarded/included to a URL with parameters, either supplementing or overriding the
         * saved request values.
         * <p>
         * In this case, the value from the wrapped request should be used.
         * <p>
         * If the value from the wrapped request is null, an attempt will be made to retrieve
         * the parameter from the saved request.
         */
        @Override
        public String getParameter(String name) {
            String value = super.getParameter(name);

            if (value != null) {
                return value;
            }

            String[] values = savedRequest.getParameterValues(name);

            if (values == null || values.length == 0) {
                return null;
            }

            return values[0];
        }

        @Override
        @SuppressWarnings("unchecked")
        public Map getParameterMap() {
            Set<String> names = getCombinedParameterNames();
            Map<String, String[]> parameterMap = new HashMap<>(names.size());

            for (String name : names) {
                parameterMap.put(name, getParameterValues(name));
            }

            return parameterMap;
        }

        @SuppressWarnings("unchecked")
        private Set<String> getCombinedParameterNames() {
            Set<String> names = new HashSet<>();
            names.addAll(super.getParameterMap().keySet());
            names.addAll(savedRequest.getParameterMap().keySet());

            return names;
        }

        @Override
        @SuppressWarnings("unchecked")
        public Enumeration getParameterNames() {
            return new Enumerator(getCombinedParameterNames());
        }

        @Override
        public String[] getParameterValues(String name) {
            String[] savedRequestParams = savedRequest.getParameterValues(name);
            String[] wrappedRequestParams = super.getParameterValues(name);

            if (savedRequestParams == null) {
                return wrappedRequestParams;
            }

            if (wrappedRequestParams == null) {
                return savedRequestParams;
            }

            // We have parameters in both saved and wrapped requests so have to merge them
            List<String> wrappedParamsList = Arrays.asList(wrappedRequestParams);
            List<String> combinedParams = new ArrayList<>(wrappedParamsList);

            // We want to add all parameters of the saved request *apart from* duplicates of
            // those already added
            for (String savedRequestParam : savedRequestParams) {
                if (!wrappedParamsList.contains(savedRequestParam)) {
                    combinedParams.add(savedRequestParam);
                }
            }

            return combinedParams.toArray(new String[combinedParams.size()]);
        }
    }
}
