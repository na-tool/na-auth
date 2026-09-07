package com.na.auth.security;

import com.alibaba.fastjson2.JSONObject;
import com.na.auth.AutoAuthConfig;
import com.na.auth.annotation.AnonymousAccess;
import com.na.auth.annotation.AuthNotCheckedApi;
import com.na.auth.service.IAuthCheckedService;
import com.na.auth.utils.AuthUtil;
import com.na.common.result.Result;
import com.na.common.result.enums.Status;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.method.HandlerMethod;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Set;

/**
 * JWT 鉴权过滤器。
 *
 * <p>每个请求只执行一次（继承自 {@link OncePerRequestFilter}），处理流程：</p>
 * <ol>
 *   <li>OPTIONS 预检请求直接放行</li>
 *   <li>方法带 {@link AnonymousAccess} 注解直接放行</li>
 *   <li>命中放行 URL 列表（skipApis）则放行</li>
 *   <li>执行 Token 校验：{@link IAuthCheckedService#handleTokenChecked}</li>
 *   <li>方法带 {@link AuthNotCheckedApi} 注解时仅注入简单用户信息后放行</li>
 *   <li>否则注入完整用户信息 + 权限校验</li>
 * </ol>
 *
 * <p>任意环节失败或抛异常，统一返回 {@link Status#USER_NO_ACCESS}。</p>
 */
@Slf4j
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    /** 路径匹配器，AntPathMatcher 是线程安全的，可全局复用 */
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    @Autowired
    private AutoAuthConfig autoAuthConfig;

    @Autowired
    private IAuthCheckedService authCheckedService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            // 1. 跨域预检请求直接放行
            if (HttpMethod.OPTIONS.toString().equals(request.getMethod())) {
                filterChain.doFilter(request, response);
                return;
            }

            // 2. 解析当前请求对应的 Controller 方法
            HandlerMethod handlerMethod = AuthUtil.getHandlerMethod(request);
            Method method = null;
            if (handlerMethod != null) {
                method = handlerMethod.getMethod();
                if (method != null && AuthUtil.hasAnnotation(method, AnonymousAccess.class)) {
                    // 方法标注 @NaAnonymousAccess：完全匿名访问
                    filterChain.doFilter(request, response);
                    return;
                }
            }

            // 3. 判断是否命中放行 URL 列表；未命中则进入鉴权流程
            boolean inSkipApis = Arrays.stream(autoAuthConfig.skipApis())
                    .map(url -> autoAuthConfig.getServlet() + url)
                    .anyMatch(url -> PATH_MATCHER.match(url, request.getRequestURI()));

            if (!inSkipApis) {
                // 3.1 校验 Token 合法性
                if (!authCheckedService.handleTokenChecked(request, response)) {
                    setResponse(response);
                    return;
                }

                // 3.2 仅需登录信息、不需权限校验的接口
                if (method != null && AuthUtil.hasAnnotation(method, AuthNotCheckedApi.class)) {
                    if (authCheckedService.setSimpleAuthUserModel(request, response)) {
                        filterChain.doFilter(request, response);
                        return;
                    }
                }

                // 3.3 注入完整用户信息（含角色权限）
                authCheckedService.setAuthUserModel(request, response);

                if (SecurityContextHolder.getContext() == null
                        || SecurityContextHolder.getContext().getAuthentication() == null) {
                    setResponse(response);
                    return;
                }

                // 3.4 权限 URL 匹配：去掉 context-path 前缀后再校验
                String requestUri = request.getRequestURI();
                String servletPrefix = autoAuthConfig.getServlet();
                if (!servletPrefix.isEmpty() && requestUri.startsWith(servletPrefix)) {
                    requestUri = requestUri.substring(servletPrefix.length());
                }

                Set<String> requestUris = authCheckedService.getRequestApi(request);
                if (CollectionUtils.isEmpty(requestUris)) {
                    setResponse(response);
                    return;
                }
                if (!AuthUtil.checkUri(requestUris, requestUri)) {
                    setResponse(response);
                    return;
                }
            }
        } catch (Exception e) {
            // 鉴权异常：统一返回无权限，避免暴露内部错误信息
            log.error("鉴权过滤器发生异常, uri={}, msg={}", request.getRequestURI(), e.getMessage(), e);
            setResponse(response);
            return;
        }
        filterChain.doFilter(request, response);
    }

    /**
     * 统一构造 403 鉴权失败响应。
     * <p>使用 HTTP 200 + 业务码方式返回，便于前端统一处理。</p>
     */
    private void setResponse(HttpServletResponse response) throws IOException {
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        response.getWriter().write(JSONObject.toJSONString(Result.error(Status.USER_NO_ACCESS)));
    }
}
