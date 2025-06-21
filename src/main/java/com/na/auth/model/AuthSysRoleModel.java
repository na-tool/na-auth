package com.na.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthSysRoleModel implements Serializable {
    private static final long serialVersionUID = 1L;
    private String id;
    private String roleName;
    private String roleCode;
    private Integer roleSort;
    private String dataScope;
    private Boolean status;
    private Long createTime;
    private Long updateTime;
    private String roleType;

    private String tenantId;
    private String tenantName;
}
