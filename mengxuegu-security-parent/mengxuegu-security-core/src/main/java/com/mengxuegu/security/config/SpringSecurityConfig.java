package com.mengxuegu.security.config;

import com.mengxuegu.security.properites.SecurityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;

import javax.sql.DataSource;

/**
 * @program: mengxuegu-security-parent
 * @description: SpringSecurityConfig
 * @author: daiyunbo
 * @create: 2020-08-10 11:24
 **/
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    DataSource dataSource;

    @Autowired
    UserDetailsService customUserDetailsService;
    // 配置文件参数
    @Autowired
    private SecurityProperties securityProperties;

    @Autowired
    private AuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler customAuthenticationFailureHandler;
    Logger logger = LoggerFactory.getLogger(getClass());

    @Bean
    public PasswordEncoder passwordEncoder() {
        // 明文+随机盐值》加密存储
        return new BCryptPasswordEncoder();
    }
    /**
     * 记住我功能
     * @return
     */
    @Bean
    public JdbcTokenRepositoryImpl jdbcTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        // 是否启动项目时自动创建表，true自动创建
        jdbcTokenRepository.setCreateTableOnStartup(true);
        return jdbcTokenRepository;
    }
    /**
     * 认证管理器：
     * 1. 认证信息（用户名，密码）
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        // 数据库存储的密码必须是加密后的，不然会报错：There is no PasswordEncoder mapped for the id "null"
//        String password = passwordEncoder().encode("123");
//        logger.info("加密之后存储的密码：" + password);
//        /**
//         * 通过内存存储来进行用户登录
//         */
//        auth.inMemoryAuthentication().withUser("dyb")
//                .password(password).authorities("ADMIN");
        /**
         * 通过存储方式来进行用户登录
         */
        auth.userDetailsService(customUserDetailsService);
    }

    /**
     * 一般是针对静态资源放行
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web){
        web.ignoring().antMatchers("/dist/**", "/modules/**", "/plugins/**");
    }

    /**
     * 当你认证成功之后 ，springsecurity它会重写向到你上一次请求上
     * 资源权限配置：
     * 1. 被拦截的资源
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.httpBasic() // 采用 httpBasic认证方式
        http.formLogin() // 表单登录方式
                .loginPage(securityProperties.getAuthentication().getLoginPage())
                .loginProcessingUrl(securityProperties.getAuthentication().getLoginProcessingUrl()) // 登录表单提交处理url, 默认是/login
                .usernameParameter(securityProperties.getAuthentication().getUsernameParameter()) //默认的是 username
                .passwordParameter(securityProperties.getAuthentication().getPasswordParameter())  // 默认的是 password
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler)
                .and()
                .authorizeRequests() // 认证请求
                .antMatchers(securityProperties.getAuthentication().getLoginPage(),
                "/code/image").permitAll() // 放行/login/page不需要认证可访问
                .antMatchers(securityProperties.getAuthentication().getLoginPage()).permitAll() // 放行/login/page不需要认证可访问
                .anyRequest().authenticated() //所有访问该应用的http请求都要通过身份认证才可以访问
                .and()
                .rememberMe() // 记住功能配置
                .tokenRepository(jdbcTokenRepository()) //保存登录信息
                .tokenValiditySeconds(60*60*24*7) //记住我有效时长
        ; // 注意不要少了分号
    }
}
