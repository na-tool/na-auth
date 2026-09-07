package com.na.auth.security.handler;

import com.alibaba.fastjson2.JSONObject;
import com.na.common.result.Result;
import com.na.common.result.enums.Status;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 已登录但无权限访问处理器。
 *
 * <p>触发场景：用户已通过身份认证，但访问受权限保护的资源时缺少所需权限。
 * 统一返回 HTTP 200 + 业务码，便于前端按业务码处理。</p>
 */
@Component
public class AjaxAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e)
            throws IOException, ServletException {
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        response.getWriter().write(JSONObject.toJSONString(Result.error(Status.USER_NO_ACCESS)));
    }
}
