/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

/**
 * Docker image names for the Vault containers used by the testsuite. The values are defined as Maven properties in the
 * testsuite {@code pom.xml} and passed to the tests as system properties.
 */
public final class VaultImages {

    /** Image used by the tests, see the {@code vault.docker.image} Maven property. */
    public static final String VAULT = get("vault.docker.image");

    private VaultImages() {
    }

    private static String get(String property) {
        String value = System.getProperty(property);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("System property '" + property
                    + "' is not set. It is defined in testsuite/pom.xml; set it with -D when running outside Maven.");
        }
        return value;
    }
}
