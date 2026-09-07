package com.na.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 密码编码器配置。
 *
 * <p>统一暴露 {@link PasswordEncoder} Bean，供业务侧通过依赖注入完成密码哈希与校验。
 * 默认实现采用 {@link BCryptPasswordEncoder}（自带随机盐）。</p>
 *
 * <p>使用示例：</p>
 * <pre>
 * &#64;Autowired
 * private PasswordEncoder passwordEncoder;
 *
 * // 加密
 * String hash = passwordEncoder.encode(rawPassword);
 * // 校验
 * boolean ok = passwordEncoder.matches(rawPassword, hash);
 * </pre>
 */
@Configuration
public class PasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
