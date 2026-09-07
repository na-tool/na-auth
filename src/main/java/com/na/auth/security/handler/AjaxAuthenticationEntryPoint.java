package com.na.auth.security.handler;

import com.alibaba.fastjson2.JSONObject;
import com.na.common.result.Result;
import com.na.common.result.enums.Status;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 未登录访问处理器。
 *
 * <p>触发场景：访问受保护资源时 Spring Security 上下文中不存在已认证用户。
 * 统一返回 HTTP 200 + 业务码，便于前端按业务码处理。</p>
 */
@Component
public class AjaxAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
            throws IOException, ServletException {
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write(JSONObject.toJSONString(Result.error(Status.USER_NEED_AUTHORITIES)));
    }
}
