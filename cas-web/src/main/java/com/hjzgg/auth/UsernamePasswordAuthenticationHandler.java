package com.hjzgg.auth;

import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.jasig.cas.authentication.handler.DefaultPasswordEncoder;
import org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.principal.DefaultPrincipalFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.security.auth.login.FailedLoginException;
import java.security.GeneralSecurityException;

public class UsernamePasswordAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {
    @Autowired
    private DefaultPrincipalFactory defaultPrincipalFactory;

    @Override
    protected HandlerResult authenticateUsernamePasswordInternal(UsernamePasswordCredential usernamePasswordCredential) throws GeneralSecurityException, PreventedException {
        DefaultPasswordEncoder passwordEncoder = new DefaultPasswordEncoder("SHA1");
        if("hjzgg".equals(usernamePasswordCredential.getUsername())
                && passwordEncoder.encode(usernamePasswordCredential.getPassword()).equals("40bd001563085fc35165329ea1ff5c5ecbdbbeef")) {//"123"进行SHA1加密的结果, 不论是查数据库还是rest请求来获取到密码
            return createHandlerResult(usernamePasswordCredential, defaultPrincipalFactory.createPrincipal(usernamePasswordCredential.getUsername()), null);
        }
        throw new FailedLoginException();
    }
}