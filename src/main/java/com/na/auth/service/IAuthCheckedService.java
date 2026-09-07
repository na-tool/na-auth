package com.na.auth.service;

import com.na.auth.annotation.AuthNotCheckedApi;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Set;

/**
 * 鉴权校验服务接口。
 *
 * <p>由使用方（业务系统）实现该接口，向 {@link com.na.auth.security.JwtAuthenticationTokenFilter}
 * 提供 Token 解析、用户信息加载、权限查询等能力。鉴权过滤器在不同环节调用对应方法。</p>
 *
 * <p>调用顺序（由 {@code JwtAuthenticationTokenFilter} 决定）：</p>
 * <ol>
 *   <li>{@link #handleTokenChecked}：校验 Token 合法性</li>
 *   <li>{@link #setSimpleAuthUserModel} 或 {@link #setAuthUserModel}：注入登录用户信息</li>
 *   <li>{@link #getRequestApi}：返回当前用户授权可访问的 URL 集合</li>
 * </ol>
 */
public interface IAuthCheckedService {

    /**
     * 从请求中提取 Token。
     */
    String getToken(HttpServletRequest request, HttpServletResponse response);

    /**
     * 校验 Token 合法性（签名、过期、是否被踢出等）。
     *
     * @return 校验通过返回 {@code true}；失败返回 {@code false}，由过滤器返回 403
     */
    boolean handleTokenChecked(HttpServletRequest request, HttpServletResponse response);

    /**
     * 注入简单用户信息到 SecurityContext（仅基本信息，不查权限）。
     *
     * <p>用于 {@link AuthNotCheckedApi} 标注的接口。</p>
     *
     * @return 注入成功返回 {@code true}
     */
    boolean setSimpleAuthUserModel(HttpServletRequest request, HttpServletResponse response);

    /**
     * 注入完整用户信息（含角色权限）到 SecurityContext。
     */
    void setAuthUserModel(HttpServletRequest request, HttpServletResponse response);

    /**
     * 获取当前登录用户被授权可访问的 URI 集合，用于 URL 级权限匹配。
     */
    Set<String> getRequestApi(HttpServletRequest request);
}
