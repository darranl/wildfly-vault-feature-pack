/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.jboss.as.controller.security.CredentialReference.CREDENTIAL_STORE_CAPABILITY;
import static org.wildfly.extension.hashicorp.vault.CredentialStoreDefinition.HASHICORP_VAULT_CREDENTIAL_STORE_CAPABILITY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

import org.jboss.as.controller.ExpressionResolver;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.RunningMode;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.as.subsystem.test.AdditionalInitialization;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.as.version.Stability;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.ServiceContainer;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.WildFlyElytronCredentialStoreProvider;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * Integration test verifying that {@link VaultExpressionResolver} rejects a credential
 * store that is not backed by {@code HashicorpVaultCredentialStoreProvider}, even when a
 * legitimate HashiCorp Vault credential store is registered in the same service container.
 *
 * <p>A real Vault instance is started via Testcontainers and wired up as the subsystem's
 * {@code vault-store} credential store. A file-backed PKCS12 {@link KeyStoreCredentialStore}
 * is populated with the same alias and registered directly into the kernel's
 * {@link ServiceContainer} under the capability service name the resolver would compute for
 * {@code file-store}. The test then asserts:
 * <ul>
 *   <li>Resolving against {@code vault-store} (the Vault-backed store) succeeds.</li>
 *   <li>Resolving against {@code file-store} (the PKCS12 store) is rejected with a
 *       {@link ExpressionResolver.ExpressionResolutionUserException} naming the file store.</li>
 * </ul>
 */
public class NonVaultStoreRejectionIntegrationTestCase extends SubsystemJUnit5TestCase {

    private static final String VAULT_TOKEN        = "myroot";
    private static final String VAULT_STORE_NAME   = "vault-store";
    private static final String FILE_STORE_NAME    = "file-store";
    private static final String TEST_ALIAS         = "integration?rejection_test";
    private static final String TEST_SECRET        = "top-secret-value";

    private static final PathAddress SUBSYSTEM_ADDRESS =
            PathAddress.pathAddress(PathElement.pathElement("subsystem", VaultExtension.SUBSYSTEM_NAME));
    private static final PathAddress VAULT_STORE_ADDRESS =
            SUBSYSTEM_ADDRESS.append("credential-store", VAULT_STORE_NAME);

    private static VaultContainer<?> vault;

    private KernelServices kernelServices;
    private VaultExpressionResolver resolver;
    private Path keystoreFile;

    // -------------------------------------------------------------------------
    // Container lifecycle (once per class)
    // -------------------------------------------------------------------------

    private static synchronized void ensureVaultStarted() {
        if (vault != null) return;
        vault = new VaultContainer<>(DockerImageName.parse("hashicorp/vault:1.21"))
                .withVaultToken(VAULT_TOKEN);
        vault.start();
    }

    @BeforeAll
    static void startVault() {
        ensureVaultStarted();
    }

    @AfterAll
    static void stopVault() {
        if (vault != null) {
            vault.stop();
            vault = null;
        }
    }

    // -------------------------------------------------------------------------
    // Subsystem wiring
    // -------------------------------------------------------------------------

    @Override
    protected AdditionalInitialization createAdditionalInitialization() {
        return new AdditionalInitialization.ManagementAdditionalInitialization(Stability.DEFAULT) {
            @Override
            protected RunningMode getRunningMode() {
                return RunningMode.NORMAL;
            }
        };
    }

    @Override
    protected String getSubsystemXml() {
        ensureVaultStarted();
        return "<subsystem xmlns=\"urn:wildfly:hashicorp-vault:1.0\">\n"
                + "    <credential-store name=\"" + VAULT_STORE_NAME + "\""
                + " host-address=\"" + vault.getHttpHostAddress() + "\">\n"
                + "        <credential-reference clear-text=\"" + VAULT_TOKEN + "\"/>\n"
                + "    </credential-store>\n"
                + "</subsystem>";
    }

    // -------------------------------------------------------------------------
    // Per-test setup / teardown
    // -------------------------------------------------------------------------

    @BeforeEach
    public void bootKernelAndRegisterFileStore() throws Exception {
        kernelServices = createKernelServicesBuilder(createAdditionalInitialization())
                .setSubsystemXml(getSubsystemXml())
                .build();
        assertTrue(kernelServices.isSuccessfulBoot(),
                "Subsystem boot failed: " + kernelServices.getBootError());
        kernelServices.getContainer().awaitStability();
        resolver = new VaultExpressionResolver();

        // Store a test alias in the real Vault store so the positive assertion has something to resolve.
        // Remove first in case a previous run left it behind (Vault container is shared across tests).
        ModelNode removeStale = Util.createOperation("remove-alias", VAULT_STORE_ADDRESS);
        removeStale.get("alias").set(TEST_ALIAS);
        kernelServices.executeOperation(removeStale); // ignore outcome — alias may not exist yet

        ModelNode addAlias = Util.createOperation("add-alias", VAULT_STORE_ADDRESS);
        addAlias.get("alias").set(TEST_ALIAS);
        addAlias.get("secret-value").set(TEST_SECRET);
        ModelNode result = kernelServices.executeOperation(addAlias);
        assertEquals(SUCCESS, result.get(OUTCOME).asString(),
                "add-alias on Vault store should succeed: " + result);

        // Build a file-backed KeyStoreCredentialStore and register it in the kernel's
        // ServiceContainer under the name the resolver would look up for FILE_STORE_NAME.
        keystoreFile = Files.createTempFile("vault-rejection-test-", ".p12");
        Files.delete(keystoreFile); // KeyStoreCredentialStore creates it; an empty file causes a parse error
        CredentialStore fileStore = createAndPopulateFileStore(keystoreFile.toFile());

        ServiceName fileStoreSvcName =
                CredentialStoreDefinition.CREDENTIAL_STORE_RUNTIME_CAPABILITY
                        .getCapabilityServiceName(FILE_STORE_NAME);
        kernelServices.getContainer()
                .addService(fileStoreSvcName, new org.jboss.msc.service.Service<CredentialStore>() {
                    @Override public void start(StartContext ctx) throws StartException {}
                    @Override public void stop(StopContext ctx) {}
                    @Override public CredentialStore getValue() { return fileStore; }
                })
                .install();
        kernelServices.getContainer().awaitStability();
    }

    @AfterEach
    public void cleanup() throws Exception {
        if (keystoreFile != null) {
            Files.deleteIfExists(keystoreFile);
        }
    }

    // -------------------------------------------------------------------------
    // Test methods
    // -------------------------------------------------------------------------

    /**
     * The positive side: the real Vault store resolves the alias successfully.
     * This confirms the test setup is correct before asserting the rejection.
     */
    @Test
    public void resolveExpressionSucceedsForVaultStore() {
        OperationContext ctx = mockContextRuntime(kernelServices.getContainer());
        String resolved = resolver.resolveExpression(
                "${HC_VAULT::" + VAULT_STORE_NAME + ":" + TEST_ALIAS + "}", ctx);
        assertEquals(TEST_SECRET, resolved,
                "Vault store should resolve the alias to the stored secret");
    }

    /**
     * The key assertion: the file-backed PKCS12 store is co-registered in the same
     * container, but the resolver must reject it because its provider is not
     * {@code HashicorpVaultCredentialStoreProvider}.
     */
    @Test
    public void resolveExpressionRejectsFileStoreEvenWhenVaultStoreIsPresent() {
        OperationContext ctx = mockContextRuntime(kernelServices.getContainer());

        ExpressionResolver.ExpressionResolutionUserException ex = assertThrows(
                ExpressionResolver.ExpressionResolutionUserException.class,
                () -> resolver.resolveExpression(
                        "${HC_VAULT::" + FILE_STORE_NAME + ":" + TEST_ALIAS + "}", ctx));

        assertTrue(ex.getMessage().contains("WFLYHCVT0028"),
                "Should reject the file store as non-Vault: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("'" + FILE_STORE_NAME + "'"),
                "Rejection message should identify the file store by name: " + ex.getMessage());
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static CredentialStore createAndPopulateFileStore(File file) throws Exception {
        Provider storeProvider  = WildFlyElytronCredentialStoreProvider.getInstance();
        Provider passwdProvider = WildFlyElytronPasswordProvider.getInstance();

        CredentialStore store = CredentialStore.getInstance(
                KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE, storeProvider);

        Map<String, String> attrs = new HashMap<>();
        attrs.put("location", file.getAbsolutePath());
        attrs.put("keyStoreType", "PKCS12");
        attrs.put("create", "true");

        CredentialStore.CredentialSourceProtectionParameter protection =
                new CredentialStore.CredentialSourceProtectionParameter(
                        IdentityCredentials.NONE.withCredential(
                                buildPasswordCredential("changeit".toCharArray(), passwdProvider)));

        store.initialize(attrs, protection, new Provider[]{ passwdProvider });
        store.store(TEST_ALIAS, buildPasswordCredential(TEST_SECRET.toCharArray(), passwdProvider));
        store.flush();
        return store;
    }

    private static PasswordCredential buildPasswordCredential(char[] password, Provider provider)
            throws Exception {
        PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, provider);
        return new PasswordCredential(factory.generatePassword(new ClearPasswordSpec(password)));
    }

    private static OperationContext mockContextRuntime(ServiceContainer container) {
        InvocationHandler h = (proxy, method, args) -> {
            if ("getCurrentStage".equals(method.getName())) {
                return OperationContext.Stage.RUNTIME;
            }
            if ("getCapabilityServiceName".equals(method.getName()) && args != null && args.length == 3) {
                String capabilityName = (String) args[0];
                String dynamicPart    = (String) args[1];
                if (HASHICORP_VAULT_CREDENTIAL_STORE_CAPABILITY.equals(capabilityName)) {
                    return CredentialStoreDefinition.HASHICORP_VAULT_CREDENTIAL_STORE_RUNTIME_CAPABILITY
                            .getCapabilityServiceName(dynamicPart);
                }
                if (CREDENTIAL_STORE_CAPABILITY.equals(capabilityName)) {
                    return CredentialStoreDefinition.CREDENTIAL_STORE_RUNTIME_CAPABILITY
                            .getCapabilityServiceName(dynamicPart);
                }
                return ServiceName.of("capability", capabilityName, dynamicPart);
            }
            if ("getServiceRegistry".equals(method.getName())) {
                return container;
            }
            Class<?> rt = method.getReturnType();
            if (rt == boolean.class) return false;
            if (rt == int.class || rt == Integer.class) return 0;
            if (rt == long.class  || rt == Long.class)  return 0L;
            return null;
        };
        return (OperationContext) Proxy.newProxyInstance(
                OperationContext.class.getClassLoader(),
                new Class<?>[]{ OperationContext.class },
                h);
    }
}
