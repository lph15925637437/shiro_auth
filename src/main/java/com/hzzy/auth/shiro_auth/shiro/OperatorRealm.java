package com.hzzy.auth.shiro_auth.shiro;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OperatorRealm extends AuthorizingRealm {

    public static final Logger logger = LoggerFactory.getLogger(OperatorRealm.class);

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        Integer primaryPrincipal = (Integer) principals.getPrimaryPrincipal();
        logger.info("doGetAuthorizationInfo param:{}", primaryPrincipal);
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String principal = (String) token.getPrincipal();
        logger.info("doGetAuthenticationInfo param:{}", principal);
        String init = "100001";
        if (init.equals(principal)) {
            logger.info("成功认证");
        } else {
            throw new UnknownAccountException();
        }
        return new SimpleAuthenticationInfo(principal, token.getCredentials(), getName());
    }

    public String getName() {
        return "OperatorRealm";
    }
}
