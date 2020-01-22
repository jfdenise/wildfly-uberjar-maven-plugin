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
package org.wildfly.uberjar.runtime;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.controller.client.impl.AdditionalBootCliScriptInvoker;
import org.jboss.dmr.ModelNode;
import org.wildfly.core.embedded.EmbeddedProcessFactory;
import org.wildfly.core.embedded.StandaloneServer;
import static org.wildfly.uberjar.runtime.Constants.JBOSS_SERVER_CONFIG_DIR;
import org.wildfly.uberjar.runtime._private.UberJarLogger;

/**
 *
 * @author jdenise
 */
class UberJar {

    private class ShutdownHook extends Thread {

        @Override
        public void run() {
            synchronized (UberJar.this) {
                shutdown = true;
                try {
                    log.shuttingDown();
                    // Give max 10 seconds for the server to stop before to delete jbossHome.
                    ModelNode mn = new ModelNode();
                    mn.get("address");
                    mn.get("operation").set("read-attribute");
                    mn.get("name").set("server-state");
                    for (int i = 0; i < 10; i++) {
                        try {
                            ModelControllerClient client = server.getModelControllerClient();
                            if (client != null) {
                                ModelNode ret = client.execute(mn);
                                if (ret.hasDefined("result")) {
                                    String val = ret.get("result").asString();
                                    if ("stopped".equals(val)) {
                                        log.serverStopped();
                                        break;
                                    } else {
                                        log.serverNotStopped();
                                    }
                                }
                                Thread.sleep(1000);
                            } else {
                                log.nullController();
                                break;
                            }
                        } catch (Exception ex) {
                            log.unexpectedExceptionWhileShuttingDown(ex);
                        }
                    }
                } finally {
                    cleanup();
                }
            }
        }
    }

    private UberJarLogger log = UberJarLogger.ROOT_LOGGER;

    private StandaloneServer server;
    private boolean autoConfigure;
    private boolean shutdown;
    private final UberJarServerEnvironment env;
    private boolean deleteDir;

    public UberJar(UberJarServerEnvironment env) throws Exception {
        this.env = env;
        deleteDir = !env.isNoDelete();
        if (env.getScriptFile() != null) {
            autoConfigure = true;
        }

        if (env.getDeployment() != null) {
            Path deployment = env.getJBossHome().resolve("standalone/deployments");
            File[] files = deployment.toFile().listFiles((f, name) -> {
                name = name.toLowerCase();
                return name.endsWith(".war") || name.endsWith(".jar") || name.endsWith(".ear");
            });
            if (files != null && files.length > 0) {
                throw new Exception("Deployment already exists not an hollow-jar");
            }
            Path target = deployment.resolve(env.getDeployment().getFileName());
            Files.copy(env.getDeployment(), target);
            log.installDeployment(env.getDeployment());
        }

        if (env.getExternalConfig() != null) {
            final String baseDir = env.getJBossHome().resolve("standalone").toAbsolutePath().toString();
            final String serverCfg = System.getProperty(JBOSS_SERVER_CONFIG_DIR, baseDir + File.separator
                    + "configuration" + File.separator + "standalone.xml");
            Path target = Paths.get(serverCfg);
            Files.copy(env.getExternalConfig(), target, StandardCopyOption.REPLACE_EXISTING);
        }
    }


    public void run() throws Exception {
        try {
            server = buildServer();
        } catch (RuntimeException ex) {
            cleanup();
            throw ex;
        }
        Runtime.getRuntime().addShutdownHook(new ShutdownHook());
        server.start();
        checkForRestart();
    }

    private void checkForRestart() throws Exception {
        if (autoConfigure) {
            while (true) {
                Path marker = env.getMarkerDir().resolve("wf-restart-embedded-server");
                Path doneMarker = env.getMarkerDir().resolve("wf-cli-invoker-result");
                if (Files.exists(doneMarker)) {
                    if (Files.exists(marker)) {
                        // Need to synchronize due to shutdown hook.
                        synchronized (this) {
                            if (!shutdown) {
                                log.info("Restarting server");
                                server.stop();
                                try {
                                    System.clearProperty(AdditionalBootCliScriptInvoker.CLI_SCRIPT_PROPERTY);
                                    System.clearProperty(AdditionalBootCliScriptInvoker.MARKER_DIRECTORY_PROPERTY);
                                    server = buildServer();
                                } catch (RuntimeException ex) {
                                    cleanup();
                                    throw ex;
                                }
                                server.start();
                            } else {
                                log.allreadyShutdown();
                            }
                        }
                    }
                    break;
                }
                Thread.sleep(10);
            }
        }
    }

    private void cleanup() {
        if (deleteDir) {
            log.deletingHome(env.getJBossHome());
            deleteDir(env.getJBossHome());
            deleteDir = false;
        } else {
            if (env.isTmpJBossHome()) {
                log.homeNotDeleted(env.getJBossHome());
            }
        }
        if (env.getMarkerDir() != null) {
            log.deletingMarkerDir(env.getMarkerDir());
            deleteDir(env.getMarkerDir());
        }
    }

    private StandaloneServer buildServer() throws IOException {
        final StandaloneServer serv = EmbeddedProcessFactory.createStandaloneServerWithEnv(env.getConfiguration(),
                env.isStartSuspended(), env.isEmbedded(), env.isAdminMode(), env.isReadOnly());
        return serv;
    }

    private static void deleteDir(Path root) {
        if (root == null || !Files.exists(root)) {
            return;
        }
        try {
            Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                        throws IOException {
                    try {
                        Files.delete(file);
                    } catch (IOException ex) {
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException e)
                        throws IOException {
                    if (e != null) {
                        // directory iteration failed
                        throw e;
                    }
                    try {
                        Files.delete(dir);
                    } catch (IOException ex) {
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
        }
    }
}
