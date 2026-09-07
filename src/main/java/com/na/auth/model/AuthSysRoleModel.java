package com.na.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * 角色模型（鉴权模块内部使用的精简版角色）。
 *
 * <p>主要承载用户在鉴权场景所需的角色信息，避免直接依赖业务系统的角色实体。</p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthSysRoleModel implements Serializable {

    private static final long serialVersionUID = 1L;

    /** 角色ID */
    private String id;
    /** 角色名称（展示用） */
    private String roleName;
    /** 角色编码（匹配权限用） */
    private String roleCode;
    /** 排序号 */
    private Integer roleSort;
    /** 数据权限范围（如：1全部 2本部门 3本部门及以下 等） */
    private String dataScope;
    /** 状态：true 启用，false 禁用 */
    private Boolean status;
    /** 创建时间（毫秒时间戳） */
    private Long createTime;
    /** 更新时间（毫秒时间戳） */
    private Long updateTime;
    /** 角色类型 */
    private String roleType;

    /** 租户ID */
    private String tenantId;
    /** 租户名称 */
    private String tenantName;
}
