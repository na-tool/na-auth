package com.na.auth.security;

import com.na.auth.AutoAuthConfig;
import com.na.auth.security.handler.AjaxAccessDeniedHandler;
import com.na.auth.security.handler.AjaxAuthenticationEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Spring Security 配置。
 *
 * <p>核心策略：</p>
 * <ul>
 *   <li>开启方法级权限注解 {@code @PreAuthorize} / {@code @PostAuthorize}</li>
 *   <li>禁用 CSRF（JWT 无状态方案不需要）</li>
 *   <li>开启 CORS（具体跨域配置由业务方提供）</li>
 *   <li>禁用 frameOptions 防护，便于页面嵌套</li>
 *   <li>会话策略：{@link SessionCreationPolicy#STATELESS} 无状态</li>
 *   <li>放行所有请求（{@code anyRequest().permitAll()}）—— 实际鉴权由
 *       {@link JwtAuthenticationTokenFilter} 在过滤器层完成，避免与 SecurityFilterChain
 *       的默认授权链重复</li>
 *   <li>异常统一走 {@link AjaxAccessDeniedHandler} 与 {@link AjaxAuthenticationEntryPoint}</li>
 * </ul>
 */
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SpringSecurityConf {

    @Autowired
    private AjaxAccessDeniedHandler accessDeniedHandler;

    @Autowired
    private AjaxAuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;

    @Autowired
    private AutoAuthConfig autoAuthConfig;

    /**
     * 主过滤器链构建。
     * <p>{@code naAutoAuthConfig} 通过依赖注入保留，便于未来在此扩展使用。</p>
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .cors().and()
                .csrf().disable()
                .addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
                .and()
                .headers().frameOptions().disable()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll()
                )
                .build();
    }
}
