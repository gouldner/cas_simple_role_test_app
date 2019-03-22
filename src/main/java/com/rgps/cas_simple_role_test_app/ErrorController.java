package com.rgps.cas_simple_role_test_app;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class ErrorController implements org.springframework.boot.web.servlet.error.ErrorController {
    private static final Logger logger = LoggerFactory.getLogger(ErrorController.class);

    @RequestMapping("/error")
    public String handleError() {
        logger.error("Unknown error being reported.  Just logging to capture timing of the event.");
        return "error";
    }

    @Override
    public String getErrorPath() {
        return "/error";
    }
}
