package com.hzzy.auth.shiro_auth.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class LoginController {
    public static final Logger logger = LoggerFactory.getLogger(LoginController.class);

    @RequestMapping(value = "/login")
    public String login(String username, String password) {
        //
//        Subject subject = SecurityUtils.getSubject();
//        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
//
//        try {
//            subject.login(token);
//        } catch (AuthenticationException e) {
//            logger.error("errmsg:{}", "未知账户, 不能登录");
//            return "login";
//        }



        return "/login";
    }

    @RequestMapping("/logout")
    @ResponseBody
    public String logout(){
        Subject subject = SecurityUtils.getSubject();
        subject.logout();
        return "成功退出";
    }

    @RequestMapping("/get")
    @ResponseBody
    public String get(){
        return "进入get方法";
    }

    @RequestMapping("/valid")
    @ResponseBody
    public String valid(){
        return "可以在该方法生成图片验证码";
    }
}
