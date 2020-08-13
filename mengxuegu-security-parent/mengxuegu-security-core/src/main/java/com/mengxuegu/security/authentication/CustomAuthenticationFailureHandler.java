package com.mengxuegu.security.authentication;

import com.mengxuegu.base.result.MengxueguResult;
import com.mengxuegu.security.properites.LoginResponseType;
import com.mengxuegu.security.properites.SecurityProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
/**
 * @program: mengxuegu-security-parent
 * @description:处理失败认证的
 * @author: daiyunbo
 * @create: 2020-08-12 19:40
 **/

@Component("customAuthenticationFailureHandler")
//public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Autowired
    SecurityProperties securityProperties;
//    /**
//     *
//     * @param exception 认证失败时抛出异常
//     */
//    @Override
//    public void onAuthenticationFailure(HttpServletRequest request,
//                                        HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//        // 认证失败响应JSON字符串，
//        MengxueguResult result = MengxueguResult.build(HttpStatus.UNAUTHORIZED.value(), exception.getMessage());
//        response.setContentType("application/json;charset=UTF-8");
//        response.getWriter().write(result.toJsonString());
//    }

    /**
     *
     * @param exception 认证失败时抛出异常
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        if(LoginResponseType.JSON.equals(securityProperties.getAuthentication().getLoginType())) {
            // 认证失败响应JSON字符串，
            MengxueguResult result = MengxueguResult.build(HttpStatus.UNAUTHORIZED.value(), exception.getMessage());
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(result.toJsonString());
        }else {
            // 重写向回认证页面，注意加上 ?error
            super.setDefaultFailureUrl(securityProperties.getAuthentication().getLoginPage()+"?error");
            System.out.println("exception : "+exception);
            System.out.println("request : "+request);
            System.out.println("response : "+response);
            super.onAuthenticationFailure(request, response, exception);
        }

    }
}