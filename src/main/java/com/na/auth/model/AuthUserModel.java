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

import java.util.*;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthUserModel implements UserDetails {
    private String id;
    private String userName;
    private String nickName;
    private String email;
    private String phone;
    private String avatar;
    private String tenantId;
    private Set<String> deptIds;
    private String userType;
    private String tenantName;
    private Long createTime;
    private Long updateTime;
    private Long deleteTime;
    private Boolean status;

    private List<AuthSysRoleModel> roles;

    private Set<String> perms;
    private Set<String> requestUris;

    private Integer userFrom;//用户来源  0授权系统 1外部系统
    private Map<String,Object> mapParams;
    private Long loginTime;
    private String loginIp;



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

    @Override
    public String getPassword() {
        return StringUtils.EMPTY;
    }

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

    @Override
    public boolean isEnabled() {
        return false;
    }

}
