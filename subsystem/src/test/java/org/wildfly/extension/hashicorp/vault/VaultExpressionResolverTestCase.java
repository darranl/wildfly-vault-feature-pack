/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.List;

import org.jboss.as.controller.ExpressionResolver;
import org.jboss.as.controller.OperationContext;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceRegistry;
import org.junit.Before;
import org.junit.Test;

/**
 * Basic tests for {@link VaultExpressionResolver}.
 */
public class VaultExpressionResolverTestCase {

    private VaultExpressionResolver resolver;

    @Before
    public void setUp() {
        resolver = new VaultExpressionResolver();
    }

    @Test
    public void resolveExpressionReturnsNullForTooShortExpression() {
        OperationContext ctx = mockContext(OperationContext.Stage.RUNTIME);
        assertNull(resolver.resolveExpression("${x::y}", ctx));
    }

    @Test
    public void resolveExpressionReturnsNullWhenNotWrappedInBraces() {
        OperationContext ctx = mockContext(OperationContext.Stage.RUNTIME);
        assertNull(resolver.resolveExpression("HC_VAULT::store:alias", ctx));
        assertNull(resolver.resolveExpression("${HC_VAULT::store:alias", ctx));
        assertNull(resolver.resolveExpression("HC_VAULT::store:alias}", ctx));
    }

    @Test
    public void resolveExpressionReturnsNullForNonVaultPrefix() {
        OperationContext ctx = mockContext(OperationContext.Stage.RUNTIME);
        assertNull(resolver.resolveExpression("${OTHER::store:alias}", ctx));
        assertNull(resolver.resolveExpression("${HC_VAULTX::store:alias}", ctx));
    }

    @Test
    public void resolveExpressionThrowsWhenAliasEmpty() {
        OperationContext ctx = mockContext(OperationContext.Stage.RUNTIME);
        ExpressionResolver.ExpressionResolutionUserException e = assertThrows(
                ExpressionResolver.ExpressionResolutionUserException.class,
                () -> resolver.resolveExpression("${HC_VAULT::myStore:}", ctx));
        assertTrue("Message should mention alias empty", e.getMessage().contains("alias is empty"));
    }

    @Test
    public void resolveExpressionThrowsServerExceptionInModelStage() {
        OperationContext ctx = mockContext(OperationContext.Stage.MODEL);
        ExpressionResolver.ExpressionResolutionServerException e = assertThrows(
                ExpressionResolver.ExpressionResolutionServerException.class,
                () -> resolver.resolveExpression("${HC_VAULT::myStore:myAlias}", ctx));
        assertTrue("Message should mention MODEL", e.getMessage().contains("MODEL"));
    }

    @Test
    public void resolveExpressionThrowsUserExceptionWhenStoreNotInstalled() {
        OperationContext ctx = mockContext(OperationContext.Stage.RUNTIME);
        ExpressionResolver.ExpressionResolutionUserException e = assertThrows(
                ExpressionResolver.ExpressionResolutionUserException.class,
                () -> resolver.resolveExpression("${HC_VAULT::noSuchStore:someAlias}", ctx));
        assertTrue("Message should mention not installed or not available",
                e.getMessage().contains("not installed") || e.getMessage().contains("not available"));
    }

    @Test
    public void resolveExpressionThrowsOnNullExpression() {
        OperationContext ctx = mockContext(OperationContext.Stage.RUNTIME);
        assertThrows(IllegalArgumentException.class,
                () -> resolver.resolveExpression(null, ctx));
    }

    @Test
    public void resolveExpressionThrowsOnNullContext() {
        assertThrows(IllegalArgumentException.class,
                () -> resolver.resolveExpression("${HC_VAULT::s:a}", null));
    }

    private static OperationContext mockContext(OperationContext.Stage stage) {
        ServiceRegistry registry = new ServiceRegistry() {
            @Override
            public ServiceController<?> getService(ServiceName name) {
                return null;
            }
            @Override
            public List<ServiceName> getServiceNames() {
                return Collections.emptyList();
            }
            @Override
            public ServiceController<?> getRequiredService(ServiceName name) {
                throw new IllegalStateException("No service: " + name);
            }
        };
        InvocationHandler h = new InvocationHandler() {
            @Override
            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                if ("getCurrentStage".equals(method.getName())) {
                    return stage;
                }
                if ("getCapabilityServiceName".equals(method.getName()) && args != null && args.length == 3) {
                    return ServiceName.of("capability", (String) args[0], (String) args[1]);
                }
                if ("getServiceRegistry".equals(method.getName())) {
                    return registry;
                }
                Class<?> rt = method.getReturnType();
                if (rt == boolean.class) return false;
                if (rt == int.class || rt == Integer.class) return 0;
                if (rt == long.class || rt == Long.class) return 0L;
                return null;
            }
        };
        return (OperationContext) Proxy.newProxyInstance(
                OperationContext.class.getClassLoader(),
                new Class<?>[] { OperationContext.class },
                h);
    }
}
