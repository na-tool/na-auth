package com.na.auth.service.impl;

import com.na.auth.model.AuthUserModel;
import com.na.auth.service.INaSecurityService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * {@link INaSecurityService} 占位实现。
 *
 * <p>仅返回空 {@link AuthUserModel}，用于未对接用户存储时的兜底。
 * 实际项目应覆盖此 Bean 以对接真实用户表 / SSO 数据源。</p>
 *
 * <p>覆盖示例：</p>
 * <pre>
 * &#64;Service
 * public class NaSecurityServiceImpl implements INaSecurityService {
 *     &#64;Autowired
 *     private SysUserMapper userMapper;
 *
 *     &#64;Override
 *     public UserDetails loadUserByUsername(String username) {
 *         AuthUserModel user = userMapper.loadByUsername(username);
 *         if (user == null) {
 *             throw new UsernameNotFoundException(username);
 *         }
 *         return user;
 *     }
 * }
 * </pre>
 */
@Service
public class NaSecurityServiceImpl implements INaSecurityService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 占位实现：返回空模型，业务侧需覆盖
        return new AuthUserModel();
    }
}
