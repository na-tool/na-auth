package com.na.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 鉴权模块当前登录用户模型，实现 Spring Security {@link UserDetails}。
 *
 * <p>承载用户基础信息、角色、权限、租户上下文等，供过滤器写入 SecurityContext 后由业务层
 * 通过 {@link com.na.auth.utils.NaAuthUtil#getCurrentUser()} 获取。</p>
 *
 * <p>注意：{@link #isEnabled()} 返回 {@code false} 表示禁用 Spring Security 自带的表单密码登录，
 * 本模块采用 JWT 方案不依赖密码校验流程。</p>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthUserModel implements UserDetails {

    private static final long serialVersionUID = 1L;

    /** 用户ID */
    private String id;
    /** 登录账号 */
    private String userName;
    /** 昵称 */
    private String nickName;
    /** 邮箱 */
    private String email;
    /** 手机号 */
    private String phone;
    /** 头像 URL */
    private String avatar;
    /** 租户ID */
    private String tenantId;
    /** 用户所属部门ID集合 */
    private Set<String> deptIds;
    /** 用户类型 */
    private String userType;
    /** 租户名称 */
    private String tenantName;
    /** 创建时间（毫秒时间戳） */
    private Long createTime;
    /** 更新时间（毫秒时间戳） */
    private Long updateTime;
    /** 删除时间（毫秒时间戳），用于软删除 */
    private Long deleteTime;
    /** 状态：true 启用，false 禁用 */
    private Boolean status;

    /** 用户角色集合 */
    private List<AuthSysRoleModel> roles;

    /** 权限标识集合（用于 Spring Security 的 GrantedAuthority） */
    private Set<String> perms;
    /** 用户可访问的 URI 集合（用于 URL 级权限匹配） */
    private Set<String> requestUris;

    /** 用户来源：0 授权系统，1 外部系统 */
    private Integer userFrom;
    /** 扩展参数，承载业务自定义字段 */
    private Map<String, Object> mapParams;
    /** 登录时间（毫秒时间戳） */
    private Long loginTime;
    /** 登录 IP */
    private String loginIp;

    /**
     * 将 {@link #perms} 转换为 Spring Security 的 {@link GrantedAuthority} 集合。
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> auths = new ArrayList<>();
        if (CollectionUtils.isNotEmpty(perms)) {
            for (String perm : perms) {
                auths.add(new SimpleGrantedAuthority(perm));
            }
        }
        return auths;
    }

    /**
     * 密码固定返回空字符串，鉴权不依赖该字段。
     */
    @Override
    public String getPassword() {
        return StringUtils.EMPTY;
    }

    /**
     * 账号字段返回 {@link #userName}。
     */
    @Override
    public String getUsername() {
        return userName;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 显式禁用，避免被 Spring Security 默认的密码登录流程误用。
     */
    @Override
    public boolean isEnabled() {
        return false;
    }
}
