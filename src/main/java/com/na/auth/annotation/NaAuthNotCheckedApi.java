package com.na.auth.annotation;

import java.lang.annotation.*;

/**
 * 需要获取登陆信息，但是不需要校验权限
 *
 * 主要是可以通过 @ApiIgnore Principal principal
 *  AuthUserModel model = PrincipalUtil.getAuthUserModel(principal);
 *  获取登录信息
 */

@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface NaAuthNotCheckedApi {
}
