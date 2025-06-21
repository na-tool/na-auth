package com.na.auth.security.handler;

import com.alibaba.fastjson.JSONObject;
import com.na.common.result.NaResult;
import com.na.common.result.enums.NaStatus;
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
 * 未登录
 */
@Component
public class AjaxAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        httpServletResponse.setCharacterEncoding(StandardCharsets.UTF_8.name());
        httpServletResponse.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        httpServletResponse.setStatus(HttpServletResponse.SC_OK);
        httpServletResponse
                .getWriter()
                .write(JSONObject.toJSONString(NaResult.error(NaStatus.USER_NEED_AUTHORITIES)));
    }
}
