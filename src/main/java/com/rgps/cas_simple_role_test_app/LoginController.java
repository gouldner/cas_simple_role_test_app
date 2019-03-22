package com.rgps.cas_simple_role_test_app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

@Controller
public class LoginController {

    @Autowired
    private ApplicationContext context;

    // adding /login forces use off to cas directly but returns to base url
    @RequestMapping("/login")
    public String login() {
        // Redirect to application base by returning redirect and empty context
        return "redirect:";
    }

    @RequestMapping("/")
    public String MainPage() {
        return "index";
    }

    @GetMapping("/external_login")
    public ModelAndView getLoginPage(HttpServletRequest request, HttpServletResponse response,
                                     @RequestParam("target") Optional<String> target){ Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (!auth.getPrincipal().equals("anonymousUser")) {
            if (target.isPresent()) {
                return new ModelAndView("redirect:/" + target.get());
            } else {
                return new ModelAndView("redirect:");
            }
        }

        JwtCookieRequestCache jwtCookieRequestCache = context.getBean(JwtCookieRequestCache.class);
        jwtCookieRequestCache.saveRequest(request,response);

        ModelAndView model = new ModelAndView("external_login");
        return model;
    }
}
