package com.na.auth.annotation;

import java.lang.annotation.*;

/**
 * 匿名访问
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface NaAnonymousAccess {
}
