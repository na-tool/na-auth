package com.na.auth.security;

import com.na.auth.NaAutoAuthConfig;
import com.na.auth.security.handler.AjaxAccessDeniedHandler;
import com.na.auth.security.handler.AjaxAuthenticationEntryPoint;
import com.na.auth.service.INaSecurityService;
import com.na.auth.utils.NaAuthUtil;
import com.na.common.constant.INaGlobalConst;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SpringSecurityConf extends WebSecurityConfigurerAdapter {
    @Autowired
    private AjaxAccessDeniedHandler accessDeniedHandler;
    @Autowired
    private AjaxAuthenticationEntryPoint authenticationEntryPoint;
    @Autowired
    private INaSecurityService naUserAuthService;
    @Autowired
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;
    @Autowired
    private NaAutoAuthConfig naAutoAuthConfig;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(naUserAuthService).passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // 去掉 CSRF
                .csrf().disable()
                // JWT Filter
                .addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class)
                // 授权异常
                .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
                // 防止iframe造成跨域
                .and()
                .headers()
                .frameOptions()
                .disable()
                // 不创建回话
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
//                //定义哪些URL需要被保护
//                .antMatchers(INaGlobalConst.SECURITY.ACTUATOR_URLS).authenticated()
//                //定义哪些URL需要被保护、哪些不需要被保护
//                .antMatchers(naAutoAuthConfig.skipApis()).permitAll()
//                .antMatchers(NaAuthUtil.getAnonymousAccess().toArray(new String[0])).permitAll()
                .antMatchers("/**").permitAll() // 允许所有请求
                // 所有请求都需要认证
                .anyRequest()
                .authenticated();


    }

}
