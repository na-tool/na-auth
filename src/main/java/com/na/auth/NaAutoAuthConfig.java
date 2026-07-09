package com.na.auth;

import com.na.common.constant.INaGlobalConst;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.*;

@Data
@Component
@ConfigurationProperties(prefix = "na.auth")
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class NaAutoAuthConfig {
//    private String key; // 秘钥

    private String servlet; // servlet名称

    private Long expirationSeconds; // 过期时间
    private String signingKey; // 签名秘钥

    private List<String> skipApis = new LinkedList<>(); // 跳过url

    private List<String> forceApis = new LinkedList<>(); // 强制效验跳过url

    @Autowired
    private Environment environment;

    public String getServlet() {
        if(StringUtils.isEmpty(servlet)){
            return environment.getProperty("server.servlet.context-path","");
        }
        return servlet;
    }

    public Long getExpirationSeconds() {
        if(expirationSeconds == null){
            return INaGlobalConst.SECURITY.EXPIRATION_MILLISECONDS / 1000;
        }
        return expirationSeconds;
    }

    public String getSigningKey() {
        if(StringUtils.isEmpty(signingKey)){
            return INaGlobalConst.SECURITY.STRING_KEY;
        }
        return signingKey;
    }

    public String[] skipApis() {
        // 创建一个结果集合，用于存储去重后的 skipUrls
        Set<String> resultSet = new HashSet<>();

        // 添加默认的 SKIP_URLS
        resultSet.addAll(Arrays.asList(INaGlobalConst.SECURITY.SKIP_URLS));

        // 如果 skipUrls 不为空，添加其中的元素
        if (CollectionUtils.isNotEmpty(skipApis)) {
            resultSet.addAll(skipApis);
        }
        if(CollectionUtils.isNotEmpty(forceApis)){
            resultSet.removeAll(forceApis);
        }

        // 将 Set 转成 String[] 数组
        return resultSet.toArray(new String[0]);
    }
}
