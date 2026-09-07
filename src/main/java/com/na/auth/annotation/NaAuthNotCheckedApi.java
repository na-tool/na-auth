package com.na.auth.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标注在 Controller 方法上，表示该接口需要获取登录用户信息但跳过 URL 级权限校验。
 *
 * <p>由 {@link com.na.auth.security.JwtAuthenticationTokenFilter} 在过滤器层短路识别，
 * 命中后仅调用 {@link com.na.auth.service.INaAuthCheckedService#setSimpleAuthUserModel}
 * 写入简单的用户信息到 SecurityContext，不进行 URL 权限匹配。</p>
 *
 * <p>Controller 可通过注入 {@code Principal} 获取用户：</p>
 * <pre>
 * &#64;NaAuthNotCheckedApi
 * &#64;GetMapping("/me/profile")
 * public NaResult&lt;Object&gt; profile(Principal principal) {
 *     AuthUserModel user = NaAuthUtil.getCurrentUser(principal);
 *     ...
 * }
 * </pre>
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface NaAuthNotCheckedApi {
}
