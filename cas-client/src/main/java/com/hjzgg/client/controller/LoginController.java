package com.hjzgg.client.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class LoginController {

    @RequestMapping("success")
    public String loginSussess() {
        return "success";
    }

    @RequestMapping("error")
    public String loginError() {
        return "error";
    }
}
