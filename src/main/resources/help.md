### 权限认证模块

```text
本版本发布时间为 2021-05-01  适配jdk版本为 1.8
```

#### 1 配置
##### 1.1 添加依赖
```
<dependency>
    <groupId>com.na</groupId>
    <artifactId>na-auth</artifactId>
    <version>1.0.0</version>
</dependency>
        
或者

<dependency>
    <groupId>com.na</groupId>
    <artifactId>na-auth</artifactId>
    <version>1.0.0</version>
    <scope>system</scope>
    <systemPath>${project.basedir}/../lib/na-auth-1.0.0.jar</systemPath>
</dependency>

相关依赖

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

##### 1.2 配置
```yaml
na:
  auth:
    key: 秘钥需要申请
```

##### 1.3 使用
```java
import com.na.auth.NaAutoAuthConfig;
import com.na.auth.model.AuthSysRoleModel;
import com.na.auth.model.AuthUserModel;
import com.na.auth.service.INaAuthCheckedService;
import com.na.auth.utils.NaAuthUtil;
import com.na.common.cache.NaCacheTemplate;
import com.na.common.constant.INaGlobalConst;
import com.na.common.utils.NaJwtUtil;
import com.na.common.constants.MyConst;
import com.na.controller.vo.ResLoginVO;
import com.na.core.repo.ISysResourceRepo;
import com.na.core.repo.ISysRoleRepo;
import com.na.model.SysResourceModel;
import com.na.model.SysRoleModel;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
public class MyAuthCheckedServiceImpl implements INaAuthCheckedService {

    @Autowired
    private NaAutoAuthConfig naAutoAuthConfig;
    @Autowired
    private ISysRoleRepo sysRoleRepo;
    @Autowired
    private ISysResourceRepo sysResourceRepo;

    @Override
    public String getToken(HttpServletRequest request, HttpServletResponse response) {
        String authHeader = StringUtils.trimToNull(request.getHeader(INaGlobalConst.SECURITY.HEADER_STRING));
        if (authHeader != null && authHeader.startsWith(INaGlobalConst.SECURITY.JWT_TOKEN_PREFIX)) {
            return authHeader.substring(INaGlobalConst.SECURITY.JWT_TOKEN_PREFIX.length() + 1);
        }
        return "";
    }

    /**
     * 【必须实现 第一效验】强制效验前端请求头的token和数据库中的是否一直，若想多个token生效 直接返回true
     * @param request
     * @param response
     * @return
     */
    @Override
    public boolean handleTokenChecked(HttpServletRequest request, HttpServletResponse response) {
        String frontToken = getToken(request, response);
        String userId = NaJwtUtil.parseToken(frontToken, naAutoAuthConfig.getSigningKey());
        if (StringUtils.isNotEmpty(userId) && SecurityContextHolder.getContext().getAuthentication() == null) {
            String cacheToken = NaCacheTemplate.getCache(MyConst.LOGIN.USER_TOKEN + userId, String.class);
            if(StringUtils.isNotEmpty(cacheToken)){
                return cacheToken.equals(frontToken);
            }
        }
        return false;
    }


    /**
     * 【必须实现 第二效验】设置用户简略信息，若api权限不想进入数据效验，携带正确的token即可，配合@NaAuthNotCheckedApi注解使用。
     * 例如: 获取 路由个人菜单树 所以人都有的权限。
     * 将用户的基本信息存到AuthUserModel上下文中，后续在获取用户信息时，直接从上下文中获取，无需每次都去数据库查询。
     * NaAuthUtil.getCurrentUser() 获取当前用户信息
     * 返回true 表示设置成功，返回false 表示设置失败，后续会进行【第三效验】
     * @param request
     * @param response
     * @return
     */
    @Override
    public boolean setSimpleAuthUserModel(HttpServletRequest request, HttpServletResponse response) {
        String frontToken = getToken(request, response);
        String userId = NaJwtUtil.parseToken(frontToken, naAutoAuthConfig.getSigningKey());
        if (StringUtils.isNotEmpty(userId) && SecurityContextHolder.getContext().getAuthentication() == null) {
            ResLoginVO loginVO = NaCacheTemplate.getCache(MyConst.LOGIN.USER_INFO + frontToken, ResLoginVO.class);
            if (Objects.isNull(loginVO)) {
                return false;
            }
            AuthUserModel authUserModel = new AuthUserModel();
            authUserModel.setId(userId);
            authUserModel.setTenantId(loginVO.getTenantId());
            authUserModel.setUserType(loginVO.getUserType());
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(authUserModel, null, authUserModel.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            return true;
        }
        return false;
    }

    /**
     * 【必须实现 第三效验】设置用户详细信息，对所有api进行以及【第二效验】失败，都会进入该方法
     * @param request
     * @param response
     */
    @Override
    public void setAuthUserModel(HttpServletRequest request, HttpServletResponse response) {
        String frontToken = getToken(request, response);
        if (StringUtils.isNotEmpty(frontToken)) {
            String userId = NaJwtUtil.parseToken(frontToken, naAutoAuthConfig.getSigningKey());
            if (StringUtils.isNotEmpty(userId) && SecurityContextHolder.getContext().getAuthentication() == null) {

                ResLoginVO loginVO = NaCacheTemplate.getCache(MyConst.LOGIN.USER_INFO + frontToken, ResLoginVO.class);
                if (!Objects.isNull(loginVO)) {
                    List<SysRoleModel> roleModels = sysRoleRepo.queryRoleByUserId(userId);

                    Boolean exists = roleModels.stream()
                            .anyMatch(role -> INaGlobalConst.SECURITY.SYS_MENU_DATA_SCOPE.ALL.equals(role.getDataScope()));
                    List<SysResourceModel> resourceModels = null;
                    if (exists) {
                        resourceModels = sysResourceRepo.queryAllResource();
                    } else {
                        resourceModels = sysResourceRepo.queryResourceByUserId(userId);
                    }

                    Set<String> perms = resourceModels.stream()
                            .map(SysResourceModel::getPerms)
                            .filter(perm -> perm != null && !perm.isEmpty())
                            .collect(Collectors.toSet());

                    Set<String> requestUris = resourceModels.stream()
                            .map(SysResourceModel::getRequestUri)
                            .filter(perm -> perm != null && !perm.isEmpty())
                            .collect(Collectors.toSet());

                    List<AuthSysRoleModel> roles = new ArrayList<>();
                    for (SysRoleModel roleModel : roleModels) {
                        roles.add(AuthSysRoleModel.builder()
                                .id(roleModel.getId())
                                .roleName(roleModel.getName())
                                .build());
                    }
                    AuthUserModel authUserModel = new AuthUserModel();
                    authUserModel.setId(userId);
                    authUserModel.setTenantId(loginVO.getTenantId());
                    authUserModel.setUserType(loginVO.getUserType());
                    authUserModel.setRoles(roles);
                    authUserModel.setPerms(perms);
                    authUserModel.setRequestUris(requestUris);
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(authUserModel, null, authUserModel.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }

    }

    /**
     * 【必须实现】获取当前用户拥有的api地址，用于【第三效验】
     * @param request
     * @return
     */
    @Override
    public Set<String> getRequestApi(HttpServletRequest request) {
        return NaAuthUtil.getCurrentUser().getRequestUris();
    }
}

```

```checkUri

/**
 * AntPathMatcher 路径匹配规则说明：
 *
 * requestUris 中的规则        Ant 匹配语义                    /api/v1   /api/v1/test   /api/v1/a/test   /api/v1/a/a
 * ---------------------------------------------------------------------------------------------------------------
 * /api/v1                     精确匹配                        ✔         ✘              ✘                ✘
 * /api/v1/*                   一层子路径                      ✘         ✔ (test)       ✘                ✘
 * /api/v1/*/test              一层 + test                     ✘         ✘              ✔ (a/test)       ✘
 * /api/v1/**                  任意层子路径（含 0 层）          ✔         ✔              ✔                ✔
 * /api/v1/**/test             任意层 + test                   ✘         ✔ (test)       ✔ (a/test)       ✘
 *
 * 说明：
 * 1. '*'  仅匹配一层路径，不包含 '/'。
 * 2. '**' 可匹配任意层路径（可以是 0 层）。
 * 3. '/api/v1/**' 可以匹配 '/api/v1' 本身，这是 AntPathMatcher 的标准行为。
 * 4. 行为与 Spring MVC / Spring Security 中的 antMatchers 完全一致。
 */


```


# 【注意】启动类配置
```
如果你的包名不是以com.na开头的，需要配置
@ComponentScan(basePackages = {"com.na", "com.ziji.baoming"}) // 扫描多个包路径
```
