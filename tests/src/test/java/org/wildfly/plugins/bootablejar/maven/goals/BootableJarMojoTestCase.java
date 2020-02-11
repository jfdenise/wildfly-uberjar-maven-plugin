/*
 * Copyright 2016-2020 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.plugins.bootablejar.maven.goals;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.jboss.galleon.config.ConfigId;
import org.jboss.galleon.config.ConfigModel;
import org.jboss.galleon.config.ProvisioningConfig;
import org.jboss.galleon.util.PathsUtils;
import org.jboss.galleon.util.ZipUtils;
import org.jboss.galleon.xml.ProvisioningXmlParser;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 *
 * @author jdenise
 */
// Still using JUnit3 in AbstractMojoTestCase class.
@RunWith(JUnit4.class)
public class BootableJarMojoTestCase extends AbstractConfiguredMojoTestCase {

    private static Path setupProject(String pomFileName, boolean copyWar, String provisioning, String cli) throws IOException {
        File pom = getTestFile("src/test/resources/poms/" + pomFileName);
        File war = getTestFile("src/test/resources/test.war");
        assertNotNull(pom);
        assertTrue(pom.exists());
        assertNotNull(war);
        assertTrue(war.exists());
        Path dir = Files.createTempDirectory("bootable-jar-test");
        Path pomFile = dir.resolve("pom.xml");
        Path target = Files.createDirectory(dir.resolve("target"));
        if (copyWar) {
            Files.copy(war.toPath(), target.resolve(war.getName()));
        }
        if (provisioning != null) {
            File prov = getTestFile("src/test/resources/provisioning/" + provisioning);
            assertNotNull(prov);
            assertTrue(prov.exists());
            Path galleon = Files.createDirectory(dir.resolve("galleon"));
            Files.copy(prov.toPath(), galleon.resolve("provisioning.xml"));
        }
        if (cli != null) {
            File cliFile = getTestFile("src/test/resources/cli/" + cli);
            assertNotNull(cliFile);
            assertTrue(cliFile.exists());
            Files.copy(cliFile.toPath(), dir.resolve("script.cli"));
        }
        Files.copy(pom.toPath(), pomFile);
        return dir;
    }

    @Before
    public void before() {
        // required to not have multiple run to fail with module.path
        // pointing to directory from previous run.
        // This system property is passed to the forked embedded server
        // that uses it to lookup modules.
        System.clearProperty("module.path");
        try {
            super.setUp();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    @Test
    public void testDefaultConfiguration()
            throws Exception {
        Path dir = setupProject("test1-pom.xml", true, null, null);
        try {
            BuildBootableJarMojo mojo = (BuildBootableJarMojo) lookupConfiguredMojo(dir.resolve("pom.xml").toFile(), "package");
            assertNotNull(mojo);
            assertNull(mojo.cliScriptFile);
            assertEquals("wildfly@maven(org.jboss.universe:community-universe)", mojo.defaultFpl);
            assertNotNull(mojo.projectBuildDir);
            assertTrue(mojo.excludeLayers.isEmpty());
            assertTrue(mojo.layers.isEmpty());
            assertFalse(mojo.pluginOptions.isEmpty());
            assertTrue(mojo.pluginOptions.size() == 1);
            // Not default but needed for multiple plugin invocations in the same process
            assertTrue(mojo.pluginOptions.toString(), mojo.pluginOptions.get("jboss-fork-embedded").equals("true"));
            assertFalse(mojo.devApp);
            assertFalse(mojo.devServer);
            assertFalse(mojo.hollowJar);
            assertFalse(mojo.logTime);
            assertFalse(mojo.offline);
            assertFalse(mojo.recordState);
            assertFalse(mojo.skip);
            assertTrue(mojo.rootUrlPath);
            mojo.execute();
            checkJar(dir, true, true, null, null, null);
            checkDeployment(dir, true);
        } finally {
            BuildBootableJarMojo.deleteDir(dir);
        }
    }

    @Test
    public void testLayersConfiguration()
            throws Exception {
        Path dir = setupProject("test8-pom.xml", true, null, null);
        try {
            BuildBootableJarMojo mojo = (BuildBootableJarMojo) lookupConfiguredMojo(dir.resolve("pom.xml").toFile(), "package");
            assertNotNull(mojo);
            assertFalse(mojo.layers.isEmpty());
            assertTrue(mojo.layers.size() == 1);
            assertTrue(mojo.layers.get(0).equals("jaxrs"));

            mojo.recordState = true;
            mojo.execute();
            String[] layers = {"jaxrs"};
            checkJar(dir, true, true, layers, null, null);
            checkDeployment(dir, true);
        } finally {
            BuildBootableJarMojo.deleteDir(dir);
        }
    }

    @Test
    public void testProvisioningConfiguration()
            throws Exception {
        Path dir = setupProject("test4-pom.xml", true, "provisioning1.xml", null);
        try {
            BuildBootableJarMojo mojo = (BuildBootableJarMojo) lookupConfiguredMojo(dir.resolve("pom.xml").toFile(), "package");
            assertNotNull(mojo);
            assertFalse(mojo.rootUrlPath);
            mojo.recordState = true;
            mojo.execute();
            String[] layers = {"web-server"};
            checkJar(dir, true, false, layers, null, null);
            checkDeployment(dir, false);
        } finally {
            BuildBootableJarMojo.deleteDir(dir);
        }
    }

    @Test
    public void testLayersOverrideProvisioningConfiguration()
            throws Exception {
        Path dir = setupProject("test2-pom.xml", true, "provisioning1.xml", "add-prop.cli");
        try {
            BuildBootableJarMojo mojo = (BuildBootableJarMojo) lookupConfiguredMojo(dir.resolve("pom.xml").toFile(), "package");
            assertNotNull(mojo);
            mojo.recordState = true;
            mojo.execute();
            String[] layers = {"jaxrs"};
            checkJar(dir, true, true, layers, null, "foobootable");
            checkDeployment(dir, true);
        } finally {
            BuildBootableJarMojo.deleteDir(dir);
        }
    }

    @Test
    public void testHollowJar()
            throws Exception {
        Path dir = setupProject("test3-pom.xml", true, null, null);
        try {
            BuildBootableJarMojo mojo = (BuildBootableJarMojo) lookupConfiguredMojo(dir.resolve("pom.xml").toFile(), "package");
            assertNotNull(mojo);
            assertTrue(mojo.hollowJar);
            assertTrue(mojo.layers.size() == 2);
            assertTrue(mojo.layers.get(0).equals("cloud-profile"));
            assertTrue(mojo.layers.get(1).equals("management"));
            assertTrue(mojo.excludeLayers.size() == 1);
            assertTrue(mojo.excludeLayers.get(0).equals("ee-security"));
            mojo.recordState = true;
            mojo.execute();
            String[] layers = {"cloud-profile", "management"};
            String[] excludedLayers = {"ee-security"};
            checkJar(dir, false, false, layers, excludedLayers, null);
            checkManagementItf(dir);
        } finally {
            BuildBootableJarMojo.deleteDir(dir);
        }
    }

    @Test
    public void testDevServer()
            throws Exception {
        Path dir = setupProject("test6-pom.xml", true, null, null);
        try {
            BuildBootableJarMojo mojo = (BuildBootableJarMojo) lookupConfiguredMojo(dir.resolve("pom.xml").toFile(), "package");
            assertNotNull(mojo);
            assertTrue(mojo.devServer);
            mojo.execute();
            checkJar(dir, false, false, null, null, "target/deployments");
            checkManagementItf(dir);
        } finally {
            BuildBootableJarMojo.deleteDir(dir);
        }
    }

    @Test
    public void testDevApp()
            throws Exception {
        Path dir = setupProject("test7-pom.xml", true, null, null);
        try {
            BuildBootableJarMojo mojo = (BuildBootableJarMojo) lookupConfiguredMojo(dir.resolve("pom.xml").toFile(), "package");
            assertNotNull(mojo);
            assertTrue(mojo.devApp);
            mojo.execute();
            assertFalse(Files.exists(dir.resolve("target").resolve("test-wildfly-bootable.jar")));
            assertTrue(Files.exists(dir.resolve("target").resolve("deployments").resolve("ROOT.war")));
        } finally {
            BuildBootableJarMojo.deleteDir(dir);
        }
    }

    @Test
    public void testSkip()
            throws Exception {
        Path dir = setupProject("test5-pom.xml", false, null, null);
        try {
            BuildBootableJarMojo mojo = (BuildBootableJarMojo) lookupConfiguredMojo(dir.resolve("pom.xml").toFile(), "package");
            assertNotNull(mojo);
            assertTrue(mojo.skip);
            mojo.execute();
            assertFalse(Files.exists(dir.resolve("target").resolve("test-wildfly-bootable.jar")));
        } finally {
            BuildBootableJarMojo.deleteDir(dir);
        }
    }

    private void checkJar(Path dir, boolean expectDeployment, boolean isRoot,
            String[] layers, String[] excludedLayers, String configToken) throws Exception {
        Path tmpDir = Files.createTempDirectory("bootable-jar-test-unzipped");
        Path wildflyHome = Files.createTempDirectory("bootable-jar-test-unzipped-wildfly");
        try {
            Path jar = dir.resolve("target").resolve("test-wildfly-bootable.jar");
            assertTrue(Files.exists(jar));

            ZipUtils.unzip(jar, tmpDir);
            Path zippedWildfly = tmpDir.resolve("wildfly.zip");
            assertTrue(Files.exists(zippedWildfly));

            ZipUtils.unzip(zippedWildfly, wildflyHome);
            if (expectDeployment) {
                assertTrue(Files.exists(wildflyHome.resolve("standalone/deployments/" + (isRoot ? "ROOT.war" : "test.war"))));
            } else {
                assertFalse(Files.exists(wildflyHome.resolve("standalone/deployments/" + (isRoot ? "ROOT.war" : "test.war"))));
            }
            Path configFile = wildflyHome.resolve("standalone/configuration/standalone.xml");
            assertTrue(Files.exists(configFile));
            if (layers != null) {
                Path provisioning = PathsUtils.getProvisioningXml(wildflyHome);
                assertTrue(Files.exists(provisioning));
                ProvisioningConfig config = ProvisioningXmlParser.parse(provisioning);
                ConfigModel cm = config.getDefinedConfig(new ConfigId("standalone", "standalone.xml"));
                assertTrue(config.getDefinedConfigs().toString(), cm != null);
                assertTrue(cm.getIncludedLayers().size() == layers.length);
                for (String layer : layers) {
                    assertTrue(cm.getIncludedLayers().contains(layer));
                }
                if (excludedLayers != null) {
                    for (String layer : excludedLayers) {
                        assertTrue(cm.getExcludedLayers().contains(layer));
                    }
                }
            }
            if (configToken != null) {
                String str = new String(Files.readAllBytes(configFile), "UTF-8");
                assertTrue(str.contains(configToken));
            }
        } finally {
            BuildBootableJarMojo.deleteDir(tmpDir);
            BuildBootableJarMojo.deleteDir(wildflyHome);
        }
    }

    private void checkDeployment(Path dir, boolean isRoot) throws Exception {
        checkURL(dir, "http://127.0.0.1:8080/" + (isRoot ? "" : "test"));
    }

    private void checkManagementItf(Path dir) throws Exception {
        checkURL(dir, "http://127.0.0.1:9990/management");
    }

    private void checkURL(Path dir, String url) throws Exception {
        // Uncomment when we can shutdown the server

        int timeout = 30000;
        long sleep = 1000;
        boolean success = false;
        Process p = startServer(dir);
        while (timeout > 0) {
            if (checkURL(url)) {
                System.out.println("Successfully connected to " + url);
                success = true;
                break;
            }
            Thread.sleep(sleep);
            timeout -= sleep;
        }
        shutdownServer(dir, p);
        if (!success) {
            throw new Exception("Unable to interact with deployed application");
        }
    }

    private Process startServer(Path dir) throws Exception {
        String[] cmd = {"java", "-jar", dir.resolve("target").resolve("test-wildfly-bootable.jar").toString()};
        Process p = new ProcessBuilder(cmd).start();
        return p;
        //StartBootableJarMojo mojo = (StartBootableJarMojo) lookupConfiguredMojo(dir.resolve("pom.xml").toFile(), "start");
        //mojo.execute();
    }

    private void shutdownServer(Path dir, Process p) throws Exception {
        //ShutdownBootableJarMojo mojo = (ShutdownBootableJarMojo) lookupConfiguredMojo(dir.resolve("pom.xml").toFile(), "start");
        //mojo.execute();
        assertTrue(p.isAlive());
        p.destroyForcibly();
    }

    private boolean checkURL(String url) throws Exception {
        try {
            try (CloseableHttpClient httpclient = HttpClients.createDefault()) {
                HttpGet httpget = new HttpGet(url);

                CloseableHttpResponse response = httpclient.execute(httpget);
                return response.getStatusLine().getStatusCode() == 200;
            }
        } catch (Exception ex) {
            System.out.println(ex);
            return false;
        }
    }
}