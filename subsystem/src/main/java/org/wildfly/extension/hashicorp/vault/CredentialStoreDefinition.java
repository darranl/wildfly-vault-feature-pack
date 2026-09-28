/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import org.wildfly.extension.hashicorp.vault._private.HashiCorpVaultLogger;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AbstractRemoveStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ReloadRequiredWriteAttributeHandler;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleOperationDefinition;
import org.jboss.as.controller.SimpleOperationDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.descriptions.NonResolvingResourceDescriptionResolver;
import org.jboss.as.controller.descriptions.StandardResourceDescriptionResolver;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.as.controller.registry.Resource;
import org.jboss.as.controller.security.CredentialReference;
import org.jboss.as.version.Stability;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceRegistry;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.CredentialStoreExtension;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.hashicorp.vault.HashicorpVaultCredentialStoreExtension;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLContext;

import static org.jboss.as.controller.security.CredentialReference.CREDENTIAL_STORE_CAPABILITY;

/**
 * Resource definition for credential stores backed by HashiCorp Vault.
 *
 */
public class CredentialStoreDefinition extends SimpleResourceDefinition {

    static final String HOST_ADDRESS = "host-address";
    static final String NAMESPACE = "namespace";
    static final String CLIENT_SSL_CONTEXT = "client-ssl-context";

    /** Elytron capability name for client-ssl-context (used for outbound TLS). */
    private static final String CLIENT_SSL_CONTEXT_CAPABILITY = "org.wildfly.security.client-ssl-context";

    protected static final SimpleAttributeDefinition HOST_NAME_DEF =
            new SimpleAttributeDefinitionBuilder(HOST_ADDRESS, ModelType.STRING)
                    .setRequired(true)
                    .setAllowExpression(true)
                    .setXmlName(HOST_ADDRESS)
                    .setFlags(AttributeAccess.Flag.RESTART_ALL_SERVICES)
                    .setStability(Stability.DEFAULT)
                    .build();

    protected static final SimpleAttributeDefinition NAMESPACE_DEF =
            new SimpleAttributeDefinitionBuilder(NAMESPACE, ModelType.STRING)
                    .setRequired(false)
                    .setAllowExpression(true)
                    .setXmlName(NAMESPACE)
                    .setFlags(AttributeAccess.Flag.RESTART_ALL_SERVICES)
                    .setStability(Stability.DEFAULT)
                    .build();

    /**
     * Dummy attribute definition used only by the legacy schema parsers to recognise and reject
     * the old 'authentication-context' XML attribute with a helpful error message.
     * This attribute is NOT registered in the management model.
     */
    static final SimpleAttributeDefinition AUTHENTICATION_CONTEXT_LEGACY_DEF =
            new SimpleAttributeDefinitionBuilder("authentication-context", ModelType.STRING)
                    .setRequired(false)
                    .build();

    protected static final SimpleAttributeDefinition CLIENT_SSL_CONTEXT_DEF =
            new SimpleAttributeDefinitionBuilder(CLIENT_SSL_CONTEXT, ModelType.STRING)
                    .setRequired(false)
                    .setAllowExpression(false)
                    .setXmlName(CLIENT_SSL_CONTEXT)
                    .setFlags(AttributeAccess.Flag.RESTART_ALL_SERVICES)
                    .setStability(Stability.DEFAULT)
                    .setCapabilityReference(CLIENT_SSL_CONTEXT_CAPABILITY, CREDENTIAL_STORE_CAPABILITY)
                    .build();

    static final RuntimeCapability<Void> CREDENTIAL_STORE_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(CREDENTIAL_STORE_CAPABILITY, true, CredentialStore.class)
            .build();

    /**
     * Subsystem-private capability name. Only HashiCorp Vault credential stores advertise this capability,
     * which prevents {@link VaultExpressionResolver} from accidentally resolving expressions against
     * non-Vault credential stores registered under the generic Elytron capability.
     */
    static final String HASHICORP_VAULT_CREDENTIAL_STORE_CAPABILITY =
            "org.wildfly.extension.hashicorp-vault.credential-store";

    static final RuntimeCapability<Void> HASHICORP_VAULT_CREDENTIAL_STORE_RUNTIME_CAPABILITY =
            RuntimeCapability.Builder.of(HASHICORP_VAULT_CREDENTIAL_STORE_CAPABILITY, true, CredentialStore.class)
            .build();

    static final ObjectTypeAttributeDefinition CREDENTIAL_REFERENCE =
            CredentialReference.getAttributeBuilder("credential-reference", "credential-reference", true)
                    .setFlags(AttributeAccess.Flag.RESTART_ALL_SERVICES)
                    .setCapabilityReference(CREDENTIAL_STORE_CAPABILITY, CREDENTIAL_STORE_RUNTIME_CAPABILITY)
                    .setStability(Stability.DEFAULT)
                    .setRequired(false)
                    .build();

    public static final Collection<AttributeDefinition> ATTRIBUTES = List.of(HOST_NAME_DEF, NAMESPACE_DEF,
            CLIENT_SSL_CONTEXT_DEF, CREDENTIAL_REFERENCE);

    static final StandardResourceDescriptionResolver OPERATION_RESOLVER =
            new StandardResourceDescriptionResolver("credential-store.operations",
                    "org.wildfly.extension.hashicorp.vault.LocalDescriptions",
                    CredentialStoreDefinition.class.getClassLoader());

    static final SimpleAttributeDefinition ALIAS = new SimpleAttributeDefinitionBuilder("alias", ModelType.STRING, false)
            .setMinSize(1)
            .setStability(Stability.DEFAULT)
            .build();

    static final SimpleAttributeDefinition SECRET_VALUE = new SimpleAttributeDefinitionBuilder("secret-value", ModelType.STRING, false)
            .setMinSize(0)
            .setStability(Stability.DEFAULT)
            .build();

    static final SimpleAttributeDefinition PATH = new SimpleAttributeDefinitionBuilder("path", ModelType.STRING, true)
            .setMinSize(0)  // Allow empty string to list all aliases
            .setStability(Stability.DEFAULT)
            .build();

    static final SimpleAttributeDefinition RECURSIVE = new SimpleAttributeDefinitionBuilder("recursive", ModelType.BOOLEAN, true)
            .setDefaultValue(ModelNode.FALSE)
            .setStability(Stability.DEFAULT)
            .build();

    static final SimpleAttributeDefinition RECURSIVE_DEPTH = new SimpleAttributeDefinitionBuilder("recursive-depth", ModelType.INT, true)
            .setDefaultValue(new ModelNode(100))
            .setStability(Stability.DEFAULT)
            .build();

    static final SimpleAttributeDefinition MAX_NUMBER_OF_ALIASES = new SimpleAttributeDefinitionBuilder("max-number-of-aliases", ModelType.INT, true)
            .setDefaultValue(new ModelNode(10000))
            .setStability(Stability.DEFAULT)
            .build();

    private static final SimpleOperationDefinition READ_ALIASES = new SimpleOperationDefinitionBuilder("read-aliases", OPERATION_RESOLVER)
            .setParameters(PATH, RECURSIVE, RECURSIVE_DEPTH, MAX_NUMBER_OF_ALIASES)
            .setRuntimeOnly()
            .setReadOnly()
            .setStability(Stability.DEFAULT)
            .build();

    private static final SimpleOperationDefinition ADD_ALIAS = new SimpleOperationDefinitionBuilder("add-alias", OPERATION_RESOLVER)
            .setParameters(ALIAS, SECRET_VALUE)
            .setRuntimeOnly()
            .setStability(Stability.DEFAULT)
            .build();

    private static final SimpleOperationDefinition REMOVE_ALIAS = new SimpleOperationDefinitionBuilder("remove-alias", OPERATION_RESOLVER)
            .setParameters(ALIAS)
            .setRuntimeOnly()
            .setStability(Stability.DEFAULT)
            .build();

    public CredentialStoreDefinition() {
        super(new Parameters(PathElement.pathElement("credential-store", PathElement.WILDCARD_VALUE), NonResolvingResourceDescriptionResolver.INSTANCE)
                .setAddHandler(ADD_HANDLER)
                .setRemoveHandler(REMOVE_HANDLER)
                .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setCapabilities(CREDENTIAL_STORE_RUNTIME_CAPABILITY, HASHICORP_VAULT_CREDENTIAL_STORE_RUNTIME_CAPABILITY));
    }

    @Override
    public Stability getStability() {
        return Stability.DEFAULT;
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        for (AttributeDefinition attr : ATTRIBUTES) {
            resourceRegistration.registerReadWriteAttribute(attr, null, new ReloadRequiredWriteAttributeHandler(attr));
        }
    }

    @Override
    public void registerOperations(ManagementResourceRegistration resourceRegistration) {
        super.registerOperations(resourceRegistration);

        resourceRegistration.registerOperationHandler(READ_ALIASES, new RuntimeOperationHandler(this::readAliasesOperation));
        resourceRegistration.registerOperationHandler(ADD_ALIAS, new RuntimeOperationHandler(this::addAliasOperation));
        resourceRegistration.registerOperationHandler(REMOVE_ALIAS, new RuntimeOperationHandler(this::removeAliasOperation));
    }

    private static AbstractAddStepHandler ADD_HANDLER = new AbstractAddStepHandler(){

        @Override
        protected void populateModel(ModelNode operation, ModelNode model) throws OperationFailedException {
            for (AttributeDefinition attr : ATTRIBUTES) {
                attr.validateAndSet(operation, model);
            }
        }

        @Override
        protected void rollbackRuntime(OperationContext context, ModelNode operation, Resource resource) {
            try {
                CredentialReference.rollbackCredentialStoreUpdate(CREDENTIAL_REFERENCE, context, resource);
            } catch (Exception e) {
                HashiCorpVaultLogger.ROOT_LOGGER.credentialReferenceRollbackFailed(e);
            }
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model) throws OperationFailedException {
            final String name = context.getCurrentAddressValue();

            final ModelNode hostnameNode = HOST_NAME_DEF.resolveModelAttribute(context, model);
            final ModelNode namespaceNode = NAMESPACE_DEF.resolveModelAttribute(context, model);
            final ModelNode clientSslContextNode = CLIENT_SSL_CONTEXT_DEF.resolveModelAttribute(context, model);

            Map<String, String> attributes = new HashMap<>();
            if (hostnameNode.isDefined()) {
                attributes.put("host-address", hostnameNode.asString());
            }
            if (namespaceNode.isDefined()) {
                attributes.put("namespace", namespaceNode.asString());
            }

            // Enable legacy alias format support based on runtime stability level
            // At COMMUNITY stability or lower: legacy support is enabled (with deprecation warnings)
            // At DEFAULT stability or higher: legacy support is disabled (new format required)
            Stability stability = context.getStability();
            boolean supportLegacyFormat = stability.enables(Stability.COMMUNITY);
            attributes.put("support-legacy-alias-format", String.valueOf(supportLegacyFormat));

            HashiCorpVaultLogger.ROOT_LOGGER.debugf(
                "Initializing credential store '%s' with stability=%s, supportLegacyAliasFormat=%s",
                name, stability, supportLegacyFormat);

            SSLContext sslContext = null;

            if (clientSslContextNode.isDefined()) {
                String clientSslContextName = clientSslContextNode.asString();
                String sslCapability = RuntimeCapability.buildDynamicCapabilityName(CLIENT_SSL_CONTEXT_CAPABILITY, clientSslContextName);
                ServiceName clientSslContextServiceName = context.getCapabilityServiceName(sslCapability, SSLContext.class);
                ServiceController<SSLContext> sslContextServiceController = (ServiceController<SSLContext>) context.getServiceRegistry(false).getService(clientSslContextServiceName);
                if (sslContextServiceController != null) {
                    sslContext = sslContextServiceController.getValue();
                }
            }

            try {
                    ServiceName serviceName = CREDENTIAL_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName(name);

                    ExceptionSupplier<CredentialSource, Exception> credentialSourceSupplier =
                            CredentialReference.getCredentialSourceSupplier(context, CREDENTIAL_REFERENCE, model, context.getServiceTarget().addService(ServiceName.of("temp", name)));

                    String token = null;
                    if (credentialSourceSupplier != null) {
                        try {
                            CredentialSource credentialSource = credentialSourceSupplier.get();
                            if (credentialSource != null) {
                                PasswordCredential passwordCredential = credentialSource.getCredential(PasswordCredential.class);
                                if (passwordCredential != null) {
                                    ClearPassword clearPassword = passwordCredential.getPassword(ClearPassword.class);
                                    if (clearPassword != null) {
                                        token = new String(clearPassword.getPassword());
                                    }
                                }
                            }
                        } catch (IOException e) {
                            throw HashiCorpVaultLogger.ROOT_LOGGER.failedToObtainCredentialFromReference(e);
                        }
                    }

                    CredentialStore.CredentialSourceProtectionParameter protectionParameter;
                    if (token != null) {
                        protectionParameter = new CredentialStore.CredentialSourceProtectionParameter(
                            IdentityCredentials.NONE.withCredential(createCredentialFromPassword(token))
                        );
                    } else {
                        protectionParameter = new CredentialStore.CredentialSourceProtectionParameter(
                            IdentityCredentials.NONE
                        );
                    }

                    final Map<String, String> finalAttributes = attributes;
                    final CredentialStore.CredentialSourceProtectionParameter finalProtectionParameter = protectionParameter;
                    final Provider[] finalProviders = new Provider[]{WildFlyElytronPasswordProvider.getInstance()};

                    // Use the legacy addService pattern which supports ServiceController.getService()
                    // This is required for Elytron's credential-reference to work cross-subsystem
                    SSLContext finalSslContext = sslContext;
                    CredentialStoreService service = new CredentialStoreService(() ->
                            new CredentialStoreService.InitializationParams(finalAttributes, finalProtectionParameter, finalSslContext, finalProviders)
                    );

                    // Use the legacy addService with the real service name
                    ServiceBuilder<CredentialStore> serviceBuilder =
                            context.getServiceTarget().addService(serviceName, service);

                    // Also register the service under the subsystem-private capability so that
                    // VaultExpressionResolver can resolve ${HC_VAULT::...} expressions without
                    // being able to accidentally target a non-Vault credential store.
                    // MSC aliases share the same lifecycle as the primary service name: removing
                    // the primary automatically deregisters all aliases.
                    ServiceName privateServiceName = HASHICORP_VAULT_CREDENTIAL_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName(name);
                    serviceBuilder.addAliases(privateServiceName);

                    // Re-register the credential-reference dependencies on the real service builder
                    if (credentialSourceSupplier != null) {
                        CredentialReference.getCredentialSourceSupplier(context, CREDENTIAL_REFERENCE, model, serviceBuilder);
                    }

                    serviceBuilder.install();

            } catch (CredentialStoreException e) {
                throw HashiCorpVaultLogger.ROOT_LOGGER.failedToInitializeHashiCorpVaultCredentialStore(e.getMessage(), e);
            } catch (Exception e) {
                throw HashiCorpVaultLogger.ROOT_LOGGER.failedToInitializeCredentialStoreService(e.getMessage(), e);
            }
        }
    };

    private static PasswordCredential createCredentialFromPassword(String password) throws UnsupportedCredentialTypeException {
        try {
            PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, WildFlyElytronPasswordProvider.getInstance());
            return new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(password.toCharArray())));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new UnsupportedCredentialTypeException(e);
        }
    }

    private static AbstractRemoveStepHandler REMOVE_HANDLER = new AbstractRemoveStepHandler() {
        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model) throws OperationFailedException {
            final String name = context.getCurrentAddressValue();
            ServiceName serviceName = CREDENTIAL_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName(name);
            context.removeService(serviceName);
        }
    };

    private void readAliasesOperation(OperationContext context, ModelNode operation, CredentialStore credentialStore) throws OperationFailedException {
        try {
            Set<String> aliases;
            ModelNode pathNode = PATH.resolveModelAttribute(context, operation);
            String path = pathNode.asStringOrNull();

            // "#" means root of the default mount in the new alias format
            if (path == null || path.trim().isEmpty()) {
                path = "#";
            }

            boolean recursive = RECURSIVE.resolveModelAttribute(context, operation).asBooleanOrNull();
            int recursiveDepth = recursive ? RECURSIVE_DEPTH.resolveModelAttribute(context, operation).asIntOrNull() : 0;
            int maxNumberOfAliases = MAX_NUMBER_OF_ALIASES.resolveModelAttribute(context, operation).asIntOrNull();

            List<Class<? extends CredentialStoreExtension>> supportedTypes = credentialStore.getSupportedExtensionTypes();
            if (!supportedTypes.contains(HashicorpVaultCredentialStoreExtension.class)) {
                throw HashiCorpVaultLogger.ROOT_LOGGER.vaultCredentialStoreExtensionNotSupported();
            }
            HashicorpVaultCredentialStoreExtension hccse = credentialStore.getExtensionInstance(HashicorpVaultCredentialStoreExtension.class);
            aliases = hccse.getAliases(path, recursive, recursiveDepth, maxNumberOfAliases);

            List<ModelNode> list = new ArrayList<>();
            for (String alias : aliases) {
                list.add(new ModelNode(alias));
            }
            context.getResult().set(list);
        } catch (CredentialStoreException e) {
            throw HashiCorpVaultLogger.ROOT_LOGGER.unableToReadAliases(e.getMessage(), e);
        }
    }

    private void addAliasOperation(OperationContext context, ModelNode operation, CredentialStore credentialStore) throws OperationFailedException {
        try {
            String alias = ALIAS.resolveModelAttribute(context, operation).asString();
            String secretValue = SECRET_VALUE.resolveModelAttribute(context, operation).asStringOrNull();

            if (credentialStore.exists(alias, PasswordCredential.class)) {
                throw HashiCorpVaultLogger.ROOT_LOGGER.credentialAliasAlreadyExists(alias);
            }

            if (secretValue != null) {
                PasswordCredential credential = createCredentialFromPassword(secretValue);
                credentialStore.store(alias, credential);
                credentialStore.flush();
            } else {
                throw HashiCorpVaultLogger.ROOT_LOGGER.secretValueRequired();
            }
        } catch (UnsupportedCredentialTypeException e) {
            throw HashiCorpVaultLogger.ROOT_LOGGER.unsupportedCredentialType(e.getMessage(), e);
        } catch (CredentialStoreException e) {
            throw HashiCorpVaultLogger.ROOT_LOGGER.unableToAddAlias(e.getMessage(), e);
        }
    }

    private void removeAliasOperation(OperationContext context, ModelNode operation, CredentialStore credentialStore) throws OperationFailedException {
        try {
            String alias = ALIAS.resolveModelAttribute(context, operation).asString();

            if (!credentialStore.exists(alias, PasswordCredential.class)) {
                throw HashiCorpVaultLogger.ROOT_LOGGER.credentialAliasDoesNotExist(alias);
            }

            credentialStore.remove(alias, PasswordCredential.class);
            credentialStore.flush();
        } catch (CredentialStoreException e) {
            throw HashiCorpVaultLogger.ROOT_LOGGER.unableToRemoveAlias(e.getMessage(), e);
        }
    }


    private static class RuntimeOperationHandler implements OperationStepHandler {

        private final CredentialStoreOperation operation;

        RuntimeOperationHandler(CredentialStoreOperation operation) {
            this.operation = operation;
        }

        @Override
        public void execute(OperationContext context, ModelNode operation) throws OperationFailedException {
            context.addStep(new OperationStepHandler() {
                @Override
                public void execute(OperationContext context, ModelNode operation) throws OperationFailedException {
                    final String name = context.getCurrentAddressValue();

                    // Get the credential store from the service registry
                    ServiceName serviceName = CREDENTIAL_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName(name);
                    ServiceRegistry serviceRegistry = context.getServiceRegistry(false);
                    ServiceController<?> serviceController = serviceRegistry.getService(serviceName);

                    if (serviceController == null) {
                        throw HashiCorpVaultLogger.ROOT_LOGGER.credentialStoreResourceNotFound(name);
                    }

                    CredentialStore credentialStore = (CredentialStore) serviceController.getValue();
                    if (credentialStore == null) {
                        throw HashiCorpVaultLogger.ROOT_LOGGER.credentialStoreResourceNotAvailable(name);
                    }

                    RuntimeOperationHandler.this.operation.execute(context, operation, credentialStore);
                }
            }, OperationContext.Stage.RUNTIME);
        }
    }

    @FunctionalInterface
    private interface CredentialStoreOperation {
        void execute(OperationContext context, ModelNode operation, CredentialStore credentialStore) throws OperationFailedException;
    }
}
