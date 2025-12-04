package com.na.auth.security;

import com.alibaba.fastjson.JSONObject;
import com.na.auth.NaAutoAuthConfig;
import com.na.auth.annotation.NaAnonymousAccess;
import com.na.auth.annotation.NaAuthNotCheckedApi;
import com.na.auth.service.INaAuthCheckedService;
import com.na.auth.utils.NaAuthUtil;
import com.na.common.exceptions.NaBusinessException;
import com.na.common.result.NaResult;
import com.na.common.result.enums.NaStatus;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
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
 * JwtAuthenticationTokenFilter
 */
@Slf4j
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private NaAutoAuthConfig naAutoAuthConfig;
    @Autowired
    private INaAuthCheckedService naAuthCheckedService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            if (HttpMethod.OPTIONS.toString().equals(request.getMethod())) {
                filterChain.doFilter(request, response);
                return;
            }

            String key = naAutoAuthConfig != null ? naAutoAuthConfig.getKey() : null;
            if (StringUtils.isEmpty(key)) {
                throw new NaBusinessException(NaStatus.AUTHORIZATION_EXPIRED,null);
            }

            // 获取处理当前请求的方法
            HandlerMethod handlerMethod = NaAuthUtil.getHandlerMethod(request);
            Method method = null;
            if (handlerMethod != null) {
                method = handlerMethod.getMethod();
                if (method != null && NaAuthUtil.hasAnnotation(method, NaAnonymousAccess.class)) {
                    // 如果方法有 @AnonymousAccess 注解，直接放行
                    filterChain.doFilter(request, response);
                    return;
                }
            }

            AntPathMatcher antPathMatcher = new AntPathMatcher();
            /**
             * 不属于任何一个匿名可访问路径
             */
            if (Arrays.stream(naAutoAuthConfig.skipApis())
                    .map(url -> naAutoAuthConfig.getServlet() + url)
                    .noneMatch(url -> antPathMatcher.match(url, request.getRequestURI()))) {

                if(!naAuthCheckedService.handleTokenChecked(request, response)){
                    setResponse(request, response);
                    return;
                }

                if(method != null && NaAuthUtil.hasAnnotation(method, NaAuthNotCheckedApi.class)){
                    if(naAuthCheckedService.setSimpleAuthUserModel(request, response)){
                        filterChain.doFilter(request, response);
                        return;
                    }
                }

                naAuthCheckedService.setAuthUserModel(request, response);

                if (SecurityContextHolder.getContext() == null
                        || SecurityContextHolder.getContext().getAuthentication() == null) {
                    setResponse(request,response);
                    return;
                }

                // 获取请求的URI
                String requestUri = request.getRequestURI();
                if (requestUri.startsWith(naAutoAuthConfig.getServlet())) {
                    requestUri = requestUri.substring(naAutoAuthConfig.getServlet().length());  // 去除前缀
                }

                Set<String> requestUris = naAuthCheckedService.getRequestApi(request);
                if(CollectionUtils.isEmpty(requestUris)){
                    setResponse(request,response);
                    return;
                }else {
                    Boolean pass = NaAuthUtil.checkUri(requestUris, requestUri);
                    if (!pass) {
                        setResponse(request,response);
                        return;
                    }
                }

            }

        } catch (Exception e) {
            System.out.println("Authentication filter encountered an error" + e);
            setResponse(request, response);
            return;
        }
        filterChain.doFilter(request, response);
    }


    private void setResponse(HttpServletRequest request,
                             HttpServletResponse response) throws IOException {
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
//        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        response
                .getWriter()
                .write(JSONObject.toJSONString(NaResult.error(NaStatus.USER_NO_ACCESS)));
    }

}
