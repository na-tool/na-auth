package com.na.auth.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * 用户加载服务接口，扩展 Spring Security {@link UserDetailsService}。
 *
 * <p>由业务系统实现，按账号加载 {@link com.na.auth.model.AuthUserModel} 用于鉴权。
 * 默认提供 {@link com.na.auth.service.impl.NaSecurityServiceImpl} 占位实现，
 * 实际项目应覆盖该实现以对接真实用户存储。</p>
 */
public interface INaSecurityService extends UserDetailsService {

    /**
     * 按账号加载用户信息。
     *
     * @param username 登录账号
     * @return 用户详情
     * @throws UsernameNotFoundException 用户不存在时抛出
     */
    @Override
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
