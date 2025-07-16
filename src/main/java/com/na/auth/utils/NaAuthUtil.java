package com.na.auth.utils;

import com.na.auth.annotation.NaAnonymousAccess;
import com.na.auth.model.AuthUserModel;
import com.na.common.utils.NaSpringContextUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.http.HttpServletRequest;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

@Slf4j
public class NaAuthUtil {
    /**
     * 获取所有匿名访问类
     */
//    public static Set<String> getAnonymousAccess() {
//        HashSet<String> urls = new HashSet<>();
//        Map<RequestMappingInfo, HandlerMethod> handlerMethods = NaSpringContextUtil.getBean(RequestMappingHandlerMapping.class).getHandlerMethods();
//        for (Map.Entry<RequestMappingInfo, HandlerMethod> requestMethod : handlerMethods.entrySet()) {
//            HandlerMethod value = requestMethod.getValue();
//            NaAnonymousAccess methodAnnotation = value.getMethodAnnotation(NaAnonymousAccess.class);
//            if (methodAnnotation != null) {
//                Set<String> patterns = requestMethod.getKey().getPatternsCondition().getPatterns();
//                urls.addAll(patterns);
//            }
//        }
//        return urls;
//    }

    public static HandlerMethod getHandlerMethod(HttpServletRequest request) {
        // 获取当前请求对应的 HandlerMethod
        // 你需要从 Spring 的上下文中获取 HandlerMapping 并解析当前请求
        try {
            // 获取特定的 RequestMappingHandlerMapping Bean
            RequestMappingHandlerMapping handlerMapping = NaSpringContextUtil.getBean("requestMappingHandlerMapping", RequestMappingHandlerMapping.class);
//            RequestMappingHandlerMapping handlerMapping = NaSpringContextUtil.getBean(RequestMappingHandlerMapping.class);
            HandlerExecutionChain handlerExecutionChain = handlerMapping.getHandler(request);
            if (handlerExecutionChain != null) {
                Object handler = handlerExecutionChain.getHandler();
                if (handler instanceof HandlerMethod) {
                    return (HandlerMethod) handler;
                }
            }
        } catch (Exception e) {
            log.error("Failed to get handler method", e);
            System.out.println("Failed to get handler method" + e);
        }
        return null;
    }

    /**
     * 通用的注解检查方法，检查指定方法上是否存在指定的注解。
     *
     * @param method          要检查的目标方法
     * @param annotationClass 注解的类类型
     * @return 如果存在注解，返回 true；否则返回 false
     */
    public static boolean hasAnnotation(Method method, Class<? extends Annotation> annotationClass) {
        return method.isAnnotationPresent(annotationClass);
    }

    public static Boolean checkUri(Set<String> requestUris, String requestUri) {
        for (String uri : requestUris) {
            // 将 uriPattern 转换为正则表达式
            String regex = uri.replace("/*", "/[^/]*");

            // 使用 Pattern 进行匹配
            if (Pattern.matches(regex, requestUri)) {
                return true;
            }
        }
        return false;
    }

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


    public static AuthUserModel getCurrentUser(Principal principal) {
        if (principal instanceof Authentication) {
            Object user = ((Authentication) principal).getPrincipal();
            if (user instanceof AuthUserModel) {
                return (AuthUserModel) user;
            }
        }
        return getCurrentUser();
    }

}
