package com.mengxuegu.security;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
/**
 * @program: mengxuegu-security-parent
 * @description:查询数据库中的用户信息
 * @author: daiyunbo
 * @create: 2020-08-12 19:50
 **/

@Component("customUserDetailsService")
public class CustomUserDetailsService implements UserDetailsService {
    Logger logger = LoggerFactory.getLogger(getClass());


    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info("请求认证的用户名: " + username);

        // 1. 通过请求的用户名去数据库中查询用户信息
        if(!"meng".equalsIgnoreCase(username)) {
            throw new UsernameNotFoundException("用户名或密码错误");
        }
        // 假设当前这个用户在数据库当中存储的密码是1234
        String password = passwordEncoder.encode("1234");
        // 2. 查询该用户有哪一些权限

        // 3. 封装用户信息和权限信息
        // username 用户名, password 是数据库中这个用户存储的密码,
        // authorities 是权限资源标识, springsecurity会自动的判断用户是否合法,
        return new User(username, password,
                AuthorityUtils.commaSeparatedStringToAuthorityList("ADMIN"));
    }

}