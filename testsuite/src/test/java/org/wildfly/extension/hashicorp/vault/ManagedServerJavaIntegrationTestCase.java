/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Path;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.dmr.ModelNode;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/** Verifies that the managed server uses the same JDK as the Failsafe test JVM. */
@ExtendWith(ArquillianExtension.class)
@RunAsClient
public class ManagedServerJavaIntegrationTestCase {

    @Deployment
    public static JavaArchive deployment() {
        return ShrinkWrap.create(JavaArchive.class, "managed-server-java-test.jar");
    }

    @Test
    public void testManagedServerJava(@ArquillianResource ManagementClient managementClient) throws Exception {
        PathAddress runtime = PathAddress.pathAddress(
                PathElement.pathElement("core-service", "platform-mbean"),
                PathElement.pathElement("type", "runtime"));
        ModelNode operation = Util.getReadAttributeOperation(runtime, "system-properties");
        ModelNode response = managementClient.getControllerClient().execute(operation);
        assertEquals("success", response.get("outcome").asString(), response.get("failure-description").asString());
        ModelNode properties = response.get("result");
        assertEquals(System.getProperty("java.version"), properties.get("java.version").asString());
        assertEquals(System.getProperty("java.vendor"), properties.get("java.vendor").asString());
        assertEquals(Path.of(System.getProperty("java.home")).toRealPath(),
                Path.of(properties.get("java.home").asString()).toRealPath());
    }
}
