package com.na.auth.utils;

import com.na.auth.model.AuthUserModel;
import com.na.common.utils.SpringContextUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

/**
 * 鉴权工具类。
 *
 * <p>提供：</p>
 * <ul>
 *   <li>{@link #getHandlerMethod(HttpServletRequest)}：解析当前请求对应的 Controller 方法</li>
 *   <li>{@link #hasAnnotation(Method, Class)}：判断方法是否标注指定注解</li>
 *   <li>{@link #checkUri(Set, String)}：URL 通配匹配</li>
 *   <li>{@link #getCurrentUser()} / {@link #getCurrentUser(Principal)}：获取当前登录用户</li>
 * </ul>
 */
@Slf4j
public class AuthUtil {

    /** 路径匹配器，AntPathMatcher 是线程安全的，可全局复用 */
    private static final AntPathMatcher MATCHER = new AntPathMatcher();

    /**
     * 获取当前请求对应的 Controller {@link HandlerMethod}。
     *
     * <p>通过 Spring 容器中的 {@code requestMappingHandlerMapping} Bean 解析请求，
     * 用于在过滤器层提前获取目标方法上的注解信息。</p>
     *
     * @param request HTTP 请求
     * @return 对应的 HandlerMethod；解析失败或不存在时返回 {@code null}
     */
    public static HandlerMethod getHandlerMethod(HttpServletRequest request) {
        try {
            RequestMappingHandlerMapping handlerMapping =
                    SpringContextUtil.getBean("requestMappingHandlerMapping", RequestMappingHandlerMapping.class);
            HandlerExecutionChain chain = handlerMapping.getHandler(request);
            if (chain != null) {
                Object handler = chain.getHandler();
                if (handler instanceof HandlerMethod) {
                    return (HandlerMethod) handler;
                }
            }
        } catch (Exception e) {
            log.error("解析 HandlerMethod 失败, uri={}, msg={}", request.getRequestURI(), e.getMessage(), e);
        }
        return null;
    }

    /**
     * 判断方法上是否标注了指定注解。
     *
     * @param method          目标方法
     * @param annotationClass 注解类型
     * @return 存在返回 {@code true}；否则 {@code false}
     */
    public static boolean hasAnnotation(Method method, Class<? extends Annotation> annotationClass) {
        return method != null && method.isAnnotationPresent(annotationClass);
    }

    /**
     * 判断请求 URI 是否匹配任意一条权限规则。
     *
     * <p>处理逻辑：</p>
     * <ol>
     *   <li>剔除 query 参数</li>
     *   <li>统一去除 URI 与 pattern 末尾 {@code /}，避免尾部斜杠导致匹配失败</li>
     *   <li>使用 {@link AntPathMatcher} 做 Ant 风格通配匹配</li>
     * </ol>
     *
     * @param requestUris 用户被授予的 URL pattern 集合
     * @param requestUri 当前请求 URI
     * @return 命中返回 {@code true}；否则 {@code false}
     */
    public static boolean checkUri(Set<String> requestUris, String requestUri) {
        if (requestUris == null || requestUris.isEmpty() || requestUri == null) {
            return false;
        }
        // 去掉 query 参数
        int idx = requestUri.indexOf('?');
        if (idx != -1) {
            requestUri = requestUri.substring(0, idx);
        }
        // 统一去掉末尾 /
        requestUri = stripTrailingSlash(requestUri);

        for (String pattern : requestUris) {
            String uriPattern = stripTrailingSlash(pattern);
            if (MATCHER.match(uriPattern, requestUri)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 去掉字符串末尾的 {@code /}（保留根路径 {@code "/"}）。
     */
    private static String stripTrailingSlash(String uri) {
        if (uri != null && uri.length() > 1 && uri.endsWith("/")) {
            return uri.substring(0, uri.length() - 1);
        }
        return uri;
    }

    /**
     * 从 Spring Security 上下文获取当前登录用户。
     *
     * <p>排除匿名用户（{@code anonymousUser}）与未认证用户。</p>
     *
     * @return 当前登录的 {@link AuthUserModel}；不存在时返回 {@code null}
     */
    public static AuthUserModel getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null
                && authentication.isAuthenticated()
                && !(authentication.getPrincipal() instanceof String
                && "anonymousUser".equals(authentication.getPrincipal()))) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof AuthUserModel) {
                return (AuthUserModel) principal;
            }
        }
        return null;
    }

    /**
     * 优先从 {@link Principal} 获取登录用户，回退到 {@link #getCurrentUser()}。
     *
     * <p>用于 Controller 方法签名 {@code Principal principal} 注入场景。</p>
     */
    public static AuthUserModel getCurrentUser(Principal principal) {
        if (principal instanceof Authentication) {
            Object user = ((Authentication) principal).getPrincipal();
            if (user instanceof AuthUserModel) {
                return (AuthUserModel) user;
            }
        }
        return getCurrentUser();
    }

    public static void main(String[] args) {
        Set<String> requestUris = new HashSet<>();
        requestUris.add("/api/v1");
        requestUris.add("/api/v1/*");
        requestUris.add("/api/v1/*/test");
        requestUris.add("/api/v1/**");
        requestUris.add("/api/v1/**/test");
        System.out.println(checkUri(requestUris, "/api/v1"));
        System.out.println(checkUri(requestUris, "/api/v1/test"));
        System.out.println(checkUri(requestUris, "/api/v1/a/test"));
        System.out.println(checkUri(requestUris, "/api/v1/a/a/test"));
        System.out.println(checkUri(requestUris, "/api/v1"));
    }
}
