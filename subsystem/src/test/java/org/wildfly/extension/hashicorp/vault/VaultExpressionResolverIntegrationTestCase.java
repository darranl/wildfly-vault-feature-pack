/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.jboss.as.controller.security.CredentialReference.CREDENTIAL_STORE_CAPABILITY;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import org.jboss.as.controller.ExpressionResolver;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.as.subsystem.test.AdditionalInitialization;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.as.version.Stability;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.ServiceContainer;
import org.jboss.msc.service.ServiceName;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

/**
 * Integration tests for {@link VaultExpressionResolver} using Testcontainers Vault.
 */
public class VaultExpressionResolverIntegrationTestCase extends SubsystemTestCase {

    private static final String VAULT_TOKEN = "myroot";
    private static final String CREDENTIAL_STORE_NAME = "vault-store";
    private static final PathAddress SUBSYSTEM_ADDRESS = PathAddress.pathAddress(
            PathElement.pathElement("subsystem", VaultExtension.SUBSYSTEM_NAME));
    private static final PathAddress CREDENTIAL_STORE_ADDRESS = SUBSYSTEM_ADDRESS.append("credential-store", CREDENTIAL_STORE_NAME);

    private static VaultContainer<?> vault;
    private KernelServices kernelServices;
    private VaultExpressionResolver resolver;

    @BeforeClass
    public static void startVault() {
        vault = new VaultContainer<>(DockerImageName.parse("hashicorp/vault:1.21"))
                .withVaultToken(VAULT_TOKEN)
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 top_secret=password123",
                        "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass"
                );
        vault.start();
    }

    @AfterClass
    public static void stopVault() {
        if (vault != null) {
            vault.stop();
        }
    }

    @Override
    protected AdditionalInitialization createAdditionalInitialization() {
        return new AdditionalInitialization.ManagementAdditionalInitialization(Stability.COMMUNITY) {
            @Override
            protected org.jboss.as.controller.RunningMode getRunningMode() {
                return org.jboss.as.controller.RunningMode.NORMAL;
            }
        };
    }

    @Override
    protected String getSubsystemXml() {
        String hostAddress = vault.getHttpHostAddress();
        return "<subsystem xmlns=\"urn:wildfly:hashicorp-vault:community:1.0\">\n"
                + "    <credential-store name=\"" + CREDENTIAL_STORE_NAME + "\" host-address=\"" + hostAddress + "\">\n"
                + "        <credential-reference clear-text=\"" + VAULT_TOKEN + "\"/>\n"
                + "    </credential-store>\n"
                + "</subsystem>";
    }

    @Before
    public void bootKernel() throws Exception {
        kernelServices = createKernelServicesBuilder(createAdditionalInitialization())
                .setSubsystemXml(getSubsystemXml())
                .build();
        assertTrue("Subsystem boot failed: " + kernelServices.getBootError(), kernelServices.isSuccessfulBoot());
        kernelServices.getContainer().awaitStability();
        resolver = new VaultExpressionResolver();
    }

    @Test
    public void resolveExpressionReturnsStoredSecret() {
        String alias = "secret/integration.resolver_test";
        String secretValue = "resolved-secret-value";

        ModelNode addAlias = Util.createOperation("add-alias", CREDENTIAL_STORE_ADDRESS);
        addAlias.get("alias").set(alias);
        addAlias.get("secret-value").set(secretValue);
        ModelNode addResult = kernelServices.executeOperation(addAlias);
        assertEquals("add-alias should succeed: " + addResult, SUCCESS, addResult.get(OUTCOME).asString());

        String expression = "${HC_VAULT::" + CREDENTIAL_STORE_NAME + ":" + alias + "}";
        OperationContext ctx = mockContextRuntime(kernelServices.getContainer());
        String resolved = resolver.resolveExpression(expression, ctx);
        assertNotNull(resolved);
        assertEquals(secretValue, resolved);
    }

    @Test
    public void resolveExpressionThrowsWhenAliasNotFound() {
        String expression = "${HC_VAULT::" + CREDENTIAL_STORE_NAME + ":secret/nonexistent.missing}";
        OperationContext ctx = mockContextRuntime(kernelServices.getContainer());

        ExpressionResolver.ExpressionResolutionUserException e = assertThrows(
                ExpressionResolver.ExpressionResolutionUserException.class,
                () -> resolver.resolveExpression(expression, ctx));
        assertTrue("Message should mention not found or alias", e.getMessage().contains("not found"));
    }

    @Test
    public void resolveExpressionThrowsWhenStoreNotInstalled() {
        String expression = "${HC_VAULT::no-such-store:secret/some.key}";
        OperationContext ctx = mockContextRuntime(kernelServices.getContainer());

        ExpressionResolver.ExpressionResolutionUserException e = assertThrows(
                ExpressionResolver.ExpressionResolutionUserException.class,
                () -> resolver.resolveExpression(expression, ctx));
        assertTrue("Message should mention not installed or not available",
                e.getMessage().contains("not installed") || e.getMessage().contains("not available"));
    }

    /**
     * Builds an OperationContext proxy that delegates to the real kernel's service registry
     * and capability service name so the resolver can find the credential store service.
     */
    private static OperationContext mockContextRuntime(ServiceContainer container) {
        InvocationHandler h = new InvocationHandler() {
            @Override
            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                if ("getCurrentStage".equals(method.getName())) {
                    return OperationContext.Stage.RUNTIME;
                }
                if ("getCapabilityServiceName".equals(method.getName()) && args != null && args.length == 3) {
                    String capabilityName = (String) args[0];
                    String dynamicPart = (String) args[1];
                    if (CREDENTIAL_STORE_CAPABILITY.equals(capabilityName)) {
                        return CredentialStoreDefinition.CREDENTIAL_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName(dynamicPart);
                    }
                    return ServiceName.of("capability", capabilityName, dynamicPart);
                }
                if ("getServiceRegistry".equals(method.getName())) {
                    return container;
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
