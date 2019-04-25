package com.hzzy.auth.shiro_auth.config;

import com.hzzy.auth.shiro_auth.shiro.MyFormAuthenticationFilter;
import com.hzzy.auth.shiro_auth.shiro.OperatorRealm;
import com.hzzy.auth.shiro_auth.shiro.RetryLimitHashedCredentialsMatcher;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;


/**
 * shiro配置类
 * Apache Shiro 核心通过 Filter 来实现，就好像SpringMvc 通过DispachServlet 来主控制一样。
 *
 * @version V1.0
 * @author: lph
 * @date: 2019/4/24 16:36
 */
@Configuration
public class ShiroConfiguration {

    /**
     * Spring的一个bean，由Advisor决定对哪些类的方法进行AOP代理。
     *
     * @return
     */
    @Bean
    @ConditionalOnMissingBean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator creator = new DefaultAdvisorAutoProxyCreator();
        creator.setProxyTargetClass(true);
        return creator;
    }

    /**
     * 缓存管理器 使用Ehcache实现
     *
     * @return
     */
    @Bean
    public EhCacheManager getEhCacheManager() {
        EhCacheManager ehcacheManager = new EhCacheManager();
        ehcacheManager.setCacheManagerConfigFile("classpath:ehcache-shiro.xml");
        return ehcacheManager;
    }

    /**
     * 凭证匹配器
     *
     * @return
     */
    @Bean
    public RetryLimitHashedCredentialsMatcher credentialsMatcher() {
        RetryLimitHashedCredentialsMatcher Matcher = new RetryLimitHashedCredentialsMatcher(getEhCacheManager());
        Matcher.setHashAlgorithmName("md5");
        Matcher.setHashIterations(2);
        Matcher.setStoredCredentialsHexEncoded(true);
        return Matcher;
    }

    /**
     * 自定义Realm实现类处理认证授权操作
     *
     * @return
     */
    @Bean(name = "operatorReam")
    public OperatorRealm operatorRealm() {
        OperatorRealm realm = new OperatorRealm();
        realm.setCredentialsMatcher(credentialsMatcher());
        realm.setCachingEnabled(true);
        realm.setAuthorizationCachingEnabled(true);
        realm.setAuthorizationCacheName("authorizationCache");
        realm.setAuthenticationCachingEnabled(true);
        realm.setAuthenticationCacheName("authenticationCache");
        return realm;
    }

    /**
     * 安全管理器
     *
     * @return
     */
    @Bean(name = "securityManager")
    public DefaultWebSecurityManager defaultWebSecurityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(operatorRealm()); // 设置Realm
        return securityManager;
    }

    /**
     * shiro里实现的Advisor类，内部使用AopAllianceAnnotationsAuthorizingMethodInterceptor来拦截用以下注解的方法。
     *
     * @param securityManager 安全管理器
     * @return
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(DefaultWebSecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        advisor.setSecurityManager(securityManager);
        return advisor;
    }

    @Bean(name = "lifecycleBeanPostProcessor")
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

    /**
     * Shiro的Web过滤器
     *
     * @return
     */
    @Bean(name = "shiroFilter")
    public ShiroFilterFactoryBean shiroFilter() {
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        bean.setSecurityManager(defaultWebSecurityManager());
        //配置登录的url和登录成功的url
        bean.setLoginUrl("/login");
        bean.setSuccessUrl("/");
        Map<String, Filter> filters = new HashMap<String, Filter>();
        MyFormAuthenticationFilter filter = new MyFormAuthenticationFilter();
        filters.put("authc", filter);
        bean.setFilters(filters);
        LinkedHashMap<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        filterChainDefinitionMap.put("/static/**", "anon");
        filterChainDefinitionMap.put("/login", "authc");
        filterChainDefinitionMap.put("/**", "user");//表示需要认证才可以访问
        filterChainDefinitionMap.put("/logout", "logout");
        bean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return bean;
    }
}
