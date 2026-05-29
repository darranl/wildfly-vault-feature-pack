/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.wildfly.extension.hashicorp.vault.VaultExtension.SUBSYSTEM_NAME;

import java.io.IOException;

import org.jboss.as.subsystem.test.AdditionalInitialization;
import org.jboss.as.subsystem.test.AbstractSubsystemBaseTest;
import org.jboss.as.version.Stability;
import org.junit.Test;

/**
 * Verifies community namespace compatibility for the hashicorp-vault subsystem.
 */
public class CommunityCredentialStoreParsingTestCase extends AbstractSubsystemBaseTest {

    public CommunityCredentialStoreParsingTestCase() {
        super(SUBSYSTEM_NAME, new VaultExtension(), Stability.COMMUNITY);
    }

    @Override
    protected AdditionalInitialization createAdditionalInitialization() {
        return new AdditionalInitialization.ManagementAdditionalInitialization(Stability.COMMUNITY);
    }

    @Override
    protected String getSubsystemXml() throws IOException {
        return readResource("hashicorp-vault-community-1.0.xml");
    }

    @Override
    protected String getSubsystemXsdPath() throws Exception {
        return "schema/hashicorp-vault_community_1_0.xsd";
    }

    @Test
    public void testParseAndMarshalModel_EmptySubsystem() throws Exception {
        standardSubsystemTest("hashicorp-vault-community-1.0.xml", false);
    }

    @Test
    public void testParseAndMarshalModel_CredentialStore_Full() throws Exception {
        standardSubsystemTest("hashicorp-vault-community-1.0-full.xml", false);
    }

    @Override
    @Test
    public void testSubsystem() throws Exception {
        standardSubsystemTest(null, false);
    }
}
