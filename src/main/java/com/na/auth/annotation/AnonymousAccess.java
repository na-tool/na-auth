package com.na.auth.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标注在 Controller 方法上，表示该接口允许匿名访问。
 *
 * <p>由 {@link com.na.auth.security.JwtAuthenticationTokenFilter} 在过滤器层短路识别，
 * 命中即直接放行，不进行 Token 校验与权限匹配。</p>
 *
 * <p>典型用法：</p>
 * <pre>
 * &#64;NaAnonymousAccess
 * &#64;GetMapping("/open/info")
 * public NaResult&lt;Object&gt; info() { ... }
 * </pre>
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AnonymousAccess {
}
