package com.na.auth.service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Set;

public interface INaAuthCheckedService {
    String getToken(HttpServletRequest request, HttpServletResponse response);

    boolean handleTokenChecked(HttpServletRequest request, HttpServletResponse response);

    boolean setSimpleAuthUserModel(HttpServletRequest request, HttpServletResponse response);

    void setAuthUserModel(HttpServletRequest request, HttpServletResponse response);

    Set<String> getRequestApi(HttpServletRequest request);
}
