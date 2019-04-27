package com.hzzy.auth.shiro_auth.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.pam.UnsupportedTokenException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class MyFormAuthenticationFilter extends FormAuthenticationFilter {

    public static final Logger logger = LoggerFactory.getLogger(MyFormAuthenticationFilter.class);

    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        logger.info("進入MyFormAuthenticationFilter");
        if (isLoginRequest(request, response) && SecurityUtils.getSubject().isAuthenticated()) {
            try {
                WebUtils.issueRedirect(request, response, "/");
                return true;
            } catch (IOException e) {
                logger.error(e.getMessage());
                return true;
            }
        }
        else {
            HttpServletRequest httprequest = (HttpServletRequest) request;
            HttpServletResponse httpresponse = (HttpServletResponse) response;
            //判断session里是否有用户信息
            if (httprequest.getHeader("x-requested-with") != null
                    && httprequest.getHeader("x-requested-with").equalsIgnoreCase("XMLHttpRequest")) {
                //如果是ajax请求响应头会有，x-requested-with
                httpresponse.setHeader("session-status", "timeout");//在响应头设置session状态
                return false;
            }
        }
        return super.isAccessAllowed(request, response, mappedValue);
    }

    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response) throws Exception {
        HttpServletResponse httpServletResponse = (HttpServletResponse)response;
        httpServletResponse.sendRedirect("/");
        return false;
    }

    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request, ServletResponse response) {
        Map<String, Object> resultMap = new HashMap<String, Object>();
        if (e instanceof UnknownAccountException) {
            resultMap.put("errmsg", "未知账户, 不能登录");
        } else if (e instanceof DisabledAccountException) {
            resultMap.put("errmsg", "账户已被禁用, 不能登录");
        } else if (e instanceof ExcessiveAttemptsException) {
            resultMap.put("errmsg", "密码错误次数过多,请10分钟后重新登录");
        } else if (e instanceof IncorrectCredentialsException) {
            resultMap.put("errmsg", "帐号或密码错误");
        } else if (e instanceof UnsupportedTokenException){
            resultMap.put("errmsg", "帐号名称错误,或其他");
        } else {
            logger.error("登录时发生异常:" + e.getMessage());
            resultMap.put("errmsg", "登录时发生未知错误");
        }
        request.setAttribute("errmsg", "未知账户, 不能登录");

        return true;
    }

}

