package com.na.auth;

import com.na.common.constant.IGlobalConst;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 鉴权模块自动配置类。
 *
 * <p>对应配置前缀 {@code na.auth}，可在 application.yml 中通过如下方式配置：</p>
 * <pre>
 * na:
 *   auth:
 *     servlet: /api            # 应用上下文路径（缺省时取 server.servlet.context-path）
 *     expiration-seconds: 7200 # Token 过期秒数
 *     signing-key: xxx         # JWT 签名密钥
 *     skip-apis:               # 额外放行的 URL
 *       - /open/**
 *     force-apis:              # 强制校验的 URL（会从放行列表中移除）
 *       - /open/secret
 * </pre>
 *
 * <p>注意：不使用 {@link lombok.Builder}，避免把 {@code environment} 这种 Spring 注入字段
 * 也纳入 Builder，造成构造歧义。</p>
 */
@Data
@Component
@ConfigurationProperties(prefix = "na.auth")
public class AutoAuthConfig {

    /** servlet 上下文名称（一般等于 server.servlet.context-path） */
    private String servlet;

    /** Token 过期时间（秒），缺省取 {@link IGlobalConst.SECURITY#EXPIRATION_MILLISECONDS}/1000 */
    private Long expirationSeconds;

    /** JWT 签名密钥，缺省取 {@link IGlobalConst.SECURITY#STRING_KEY} */
    private String signingKey;

    /** 额外放行的 URL 列表，合并到默认 SKIP_URLS 中 */
    private List<String> skipApis = new ArrayList<>();

    /** 强制校验的 URL 列表，会从最终放行列表中移除 */
    private List<String> forceApis = new ArrayList<>();

    /**
     * Spring 环境，用于兜底读取 server.servlet.context-path 等属性。
     * 通过字段注入而非构造器注入，配合 {@link ConfigurationProperties} 后处理绑定。
     */
    @Autowired
    private Environment environment;

    /**
     * 获取 servlet 上下文路径；未配置时回退到 {@code server.servlet.context-path}。
     */
    public String getServlet() {
        if (servlet == null || servlet.isEmpty()) {
            return environment.getProperty("server.servlet.context-path", "");
        }
        return servlet;
    }

    /**
     * 获取 Token 过期秒数；未配置时使用全局默认值。
     */
    public Long getExpirationSeconds() {
        if (expirationSeconds == null) {
            return IGlobalConst.SECURITY.EXPIRATION_MILLISECONDS / 1000;
        }
        return expirationSeconds;
    }

    /**
     * 获取签名密钥；未配置时使用全局默认值。
     */
    public String getSigningKey() {
        if (signingKey == null || signingKey.isEmpty()) {
            return IGlobalConst.SECURITY.STRING_KEY;
        }
        return signingKey;
    }

    /**
     * 计算最终放行的 URL 数组。
     *
     * <p>合并策略：</p>
     * <ol>
     *   <li>加入 {@link IGlobalConst.SECURITY#SKIP_URLS} 默认放行列表</li>
     *   <li>追加用户配置的 {@link #skipApis}</li>
     *   <li>移除用户配置的 {@link #forceApis}（实现强制校验）</li>
     * </ol>
     * <p>使用 {@link HashSet} 去重，避免同一路径在多个来源中出现重复匹配。</p>
     */
    public String[] skipApis() {
        Set<String> resultSet = new HashSet<>();
        resultSet.addAll(Arrays.asList(IGlobalConst.SECURITY.SKIP_URLS));

        if (skipApis != null && !skipApis.isEmpty()) {
            resultSet.addAll(skipApis);
        }
        if (forceApis != null && !forceApis.isEmpty()) {
            resultSet.removeAll(forceApis);
        }
        return resultSet.toArray(new String[0]);
    }
}
