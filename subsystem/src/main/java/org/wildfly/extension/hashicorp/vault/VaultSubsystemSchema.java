/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.PersistentResourceXMLDescription.builder;

import java.util.EnumSet;
import java.util.Map;

import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.Feature;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.PersistentResourceXMLDescription;
import org.jboss.as.controller.PersistentSubsystemSchema;
import org.jboss.as.controller.SubsystemSchema;
import org.jboss.as.controller.xml.VersionedNamespace;
import org.jboss.as.version.Stability;
import org.jboss.staxmapper.IntVersion;

/**
 * Enumeration of hashicorp-vault subsystem schema versions.
 */
public enum VaultSubsystemSchema implements PersistentSubsystemSchema<VaultSubsystemSchema> {
    VERSION_1_0(1),
    VERSION_1_0_COMMUNITY(1, Stability.COMMUNITY),
    ;

    static final Map<Stability, VaultSubsystemSchema> CURRENT = Feature.map(EnumSet.of(VERSION_1_0));

    private final VersionedNamespace<IntVersion, VaultSubsystemSchema> namespace;

    VaultSubsystemSchema(int major) {
        this.namespace = SubsystemSchema.createSubsystemURN(VaultExtension.SUBSYSTEM_NAME, new IntVersion(major));
    }

    VaultSubsystemSchema(int major, Stability stability) {
        this.namespace = SubsystemSchema.createSubsystemURN(VaultExtension.SUBSYSTEM_NAME, stability, new IntVersion(major));
    }

    @Override
    public VersionedNamespace<IntVersion, VaultSubsystemSchema> getNamespace() {
        return this.namespace;
    }

    @Override
    public PersistentResourceXMLDescription getXMLDescription() {
        return builder(VaultExtension.SUBSYSTEM_PATH, this.getNamespace())
                .addChild(
                        builder(PathElement.pathElement("credential-store"))
                                .setXmlElementName("credential-store")
                                .setNameAttributeName("name")
                                .addAttributes(CredentialStoreDefinition.ATTRIBUTES.toArray(new AttributeDefinition[0]))
                                .build())
                .build();
    }
}
