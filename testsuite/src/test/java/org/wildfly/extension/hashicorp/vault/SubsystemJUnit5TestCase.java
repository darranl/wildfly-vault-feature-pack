/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * JUnit 5 bridge for WildFly's JUnit 4 subsystem test framework.
 *
 * Explicitly calls the parent's {@code @Before initializeParser()} and
 * {@code @After cleanup()} from Jupiter lifecycle methods, and re-declares
 * inherited {@code @org.junit.Test} methods with {@code @org.junit.jupiter.api.Test}
 * so Jupiter discovers them instead of Vintage.
 */
public abstract class SubsystemJUnit5TestCase extends SubsystemTestCase {

    @BeforeEach
    public void junitBridgeSetUp() throws Exception {
        initializeParser();
    }

    @AfterEach
    public void junitBridgeTearDown() throws Exception {
        cleanup();
    }

    @Test
    @Override
    public void testSubsystem() throws Exception {
        super.testSubsystem();
    }

    @Test
    @Override
    public void testSchema() throws Exception {
        super.testSchema();
    }
}
