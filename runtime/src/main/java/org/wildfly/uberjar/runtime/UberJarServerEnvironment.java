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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.jboss.as.controller.client.impl.AdditionalBootCliScriptInvoker;
import org.jboss.as.process.CommandLineConstants;
import org.jboss.as.server.logging.ServerLogger;
import org.jboss.as.version.ProductConfig;
import org.jboss.logmanager.LogContext;
import org.jboss.logmanager.PropertyConfigurator;
import org.wildfly.core.embedded.Configuration;
import static org.wildfly.uberjar.runtime.Constants.CLI_SCRIPT;
import static org.wildfly.uberjar.runtime.Constants.DEPLOYMENT;
import static org.wildfly.uberjar.runtime.Constants.EXTERNAL_SERVER_CONFIG;
import static org.wildfly.uberjar.runtime.Constants.JBOSS_SERVER_CONFIG_DIR;
import static org.wildfly.uberjar.runtime.Constants.JBOSS_SERVER_LOG_DIR;
import static org.wildfly.uberjar.runtime.Constants.LOG_BOOT_FILE_PROP;
import static org.wildfly.uberjar.runtime.Constants.LOG_MANAGER_CLASS;
import static org.wildfly.uberjar.runtime.Constants.LOG_MANAGER_PROP;
import static org.wildfly.uberjar.runtime.Constants.NO_DELETE_SERVER_DIR;
import static org.wildfly.uberjar.runtime.Constants.SERVER_DIR;
import org.wildfly.uberjar.runtime._private.UberJarLogger;

/**
 *
 * @author jdenise
 */
public class UberJarServerEnvironment {

    private static final Set<PosixFilePermission> EXECUTE_PERMISSIONS = new HashSet<>();
    static final String[] EXTENDED_SYSTEM_PKGS = new String[]{"org.jboss.logging", "org.jboss.logmanager"};

    static {
        EXECUTE_PERMISSIONS.add(PosixFilePermission.OWNER_EXECUTE);
        EXECUTE_PERMISSIONS.add(PosixFilePermission.OWNER_WRITE);
        EXECUTE_PERMISSIONS.add(PosixFilePermission.OWNER_READ);
        EXECUTE_PERMISSIONS.add(PosixFilePermission.GROUP_EXECUTE);
        EXECUTE_PERMISSIONS.add(PosixFilePermission.GROUP_WRITE);
        EXECUTE_PERMISSIONS.add(PosixFilePermission.GROUP_READ);
        EXECUTE_PERMISSIONS.add(PosixFilePermission.OTHERS_EXECUTE);
        EXECUTE_PERMISSIONS.add(PosixFilePermission.OTHERS_READ);
    }

    private static class Builder {

        private boolean startSuspended;
        private boolean adminMode;
        private boolean readOnly;
        private Path serverDir;
        private boolean noDelete;
        private Path scriptFile;
        private Path externalConfig;
        private Path deployment;
        private Properties systemProperties = new Properties();
        private Path markerDir;
        private Path tmpServerDir;
        private Configuration config;

        Builder addProperties(Properties systemProperties) {
            this.systemProperties.putAll(systemProperties);
            return this;
        }

        Builder setStartSuspended(boolean startSuspended) {
            this.startSuspended = startSuspended;
            return this;
        }

        Builder setAdminMode(boolean adminMode) {
            this.adminMode = adminMode;
            return this;
        }

        Builder setReadOnly(boolean readOnly) {
            this.readOnly = readOnly;
            return this;
        }

        Builder setServerDir(Path serverDir) {
            this.serverDir = serverDir;
            return this;
        }

        Builder setConfig(Configuration config) {
            this.config = config;
            return this;
        }

        Builder setTmpServerDir(Path tmpServerDir) {
            this.tmpServerDir = tmpServerDir;
            return this;
        }

        Builder setNoDelete(boolean noDelete) {
            this.noDelete = noDelete;
            return this;
        }

        public Builder setScriptFile(Path scriptFile) throws IOException {
            this.scriptFile = scriptFile;
            setAdminMode(true);
            systemProperties.setProperty(AdditionalBootCliScriptInvoker.CLI_SCRIPT_PROPERTY, scriptFile.toAbsolutePath().toString());
            markerDir = Files.createTempDirectory(null);
            systemProperties.setProperty(AdditionalBootCliScriptInvoker.MARKER_DIRECTORY_PROPERTY, markerDir.toAbsolutePath().toString());
            return this;
        }

        public Builder setExternalConfig(Path externalConfig) {
            this.externalConfig = externalConfig;
            return this;
        }

        public Builder setDeployment(Path deployment) {
            this.deployment = deployment;
            return this;
        }

        public UberJarServerEnvironment build() {
            return new UberJarServerEnvironment(startSuspended, adminMode, readOnly, serverDir,
                    noDelete,
                    scriptFile,
                    externalConfig,
                    deployment, systemProperties, markerDir, tmpServerDir, config);
        }
    }

    private final boolean startSuspended;
    private final boolean adminMode;
    private final boolean readOnly;
    private final Path serverDir;
    private final boolean noDelete;
    private final Path scriptFile;
    private final Path externalConfig;
    private final Path deployment;
    private final Path markerDir;
    private final Properties systemProperties;
    private final Path tmpServerDir;
    private final Configuration config;
    private UberJarServerEnvironment(boolean startSuspended,
            boolean adminMode,
            boolean readOnly,
            Path serverDir,
            boolean noDelete,
            Path scriptFile,
            Path externalConfig,
            Path deployment,
            Properties systemProperties,
            Path markerDir, Path tmpServerDir, Configuration config) {
        this.startSuspended = startSuspended;
        this.adminMode = adminMode;
        this.readOnly = readOnly;
        this.serverDir = serverDir;
        this.noDelete = noDelete;
        this.scriptFile = scriptFile;
        this.externalConfig = externalConfig;
        this.deployment = deployment;
        this.systemProperties = systemProperties;
        this.markerDir = markerDir;
        this.tmpServerDir = tmpServerDir;
        this.config = config;
    }

    public boolean isStartSuspended() {
        return startSuspended;
    }

    public boolean isEmbedded() {
        return false;
    }

    public boolean isAdminMode() {
        return adminMode;
    }

    public boolean isReadOnly() {
        return readOnly;
    }

    public Properties getSystemProperties() {
        return systemProperties;
    }

    /**
     * @return the serverDir
     */
    public Path getJBossHome() {
        return serverDir == null ? tmpServerDir : serverDir;
    }

    public boolean isTmpJBossHome() {
        return tmpServerDir != null;
    }

    public Path getMarkerDir() {
        return markerDir;
    }

    /**
     * @return the noDelete
     */
    public boolean isNoDelete() {
        return noDelete;
    }

    /**
     * @return the scriptFile
     */
    public Path getScriptFile() {
        return scriptFile;
    }

    /**
     * @return the externalConfig
     */
    public Path getExternalConfig() {
        return externalConfig;
    }

    /**
     * @return the deployment
     */
    public Path getDeployment() {
        return deployment;
    }

    public Configuration getConfiguration() {
        return config;
    }

    public static UberJarServerEnvironment buildEnvironment(String[] args) throws IOException, Exception {
        final int argsLength = args.length;
        UberJarServerEnvironment.Builder builder = new UberJarServerEnvironment.Builder();
        Properties systemProperties = new Properties();
        boolean isVersion = false;
        Path serverDir = null;
        for (int i = 0; i < argsLength; i++) {
            final String arg = args[i];
            try {
                if (arg.startsWith(EXTERNAL_SERVER_CONFIG)) {
                    builder.setExternalConfig(checkPath(getValue(arg)));
                } else if (arg.startsWith(DEPLOYMENT)) {
                    builder.setDeployment(checkPath(getValue(arg)));
                } else if (arg.startsWith(CLI_SCRIPT)) {
                    builder.setScriptFile(checkPath(getValue(arg)));
                } else if (arg.startsWith(SERVER_DIR)) {
                    serverDir = Paths.get(getValue(arg));
                    builder.setServerDir(serverDir);
                } else if (NO_DELETE_SERVER_DIR.equals(arg)) {
                    builder.setNoDelete(true);
                } else if (CommandLineConstants.VERSION.equals(arg) || CommandLineConstants.SHORT_VERSION.equals(arg)) {
                    isVersion = true;
                    break;
                } else if (CommandLineConstants.HELP.equals(arg) || CommandLineConstants.SHORT_HELP.equals(arg)) {
                    usage();
                    return null;
                } else if (CommandLineConstants.PROPERTIES.equals(arg)
                        || CommandLineConstants.SHORT_PROPERTIES.equals(arg)) {
                    // Set system properties from url/file
                    if (!processProperties(arg, args[++i], systemProperties)) {
                        return null;
                    }
                } else if (arg.startsWith(CommandLineConstants.PROPERTIES)) {
                    String urlSpec = parseValue(arg, CommandLineConstants.PROPERTIES);
                    if (urlSpec == null || !processProperties(arg, urlSpec, systemProperties)) {
                        return null;
                    }
                } else if (arg.startsWith(CommandLineConstants.SHORT_PROPERTIES)) {
                    String urlSpec = parseValue(arg, CommandLineConstants.SHORT_PROPERTIES);
                    if (urlSpec == null || !processProperties(arg, urlSpec, systemProperties)) {
                        return null;
                    }
                } else if (arg.startsWith(CommandLineConstants.SYS_PROP)) {

                    // set a system property
                    String name, value;
                    int idx = arg.indexOf("=");
                    if (idx == -1) {
                        name = arg.substring(2);
                        value = "true";
                    } else {
                        name = arg.substring(2, idx);
                        value = arg.substring(idx + 1, arg.length());
                    }
                    systemProperties.setProperty(name, value);
                } else if (arg.startsWith(CommandLineConstants.PUBLIC_BIND_ADDRESS)) {

                    int idx = arg.indexOf('=');
                    if (idx == arg.length() - 1) {
                        System.err.println(ServerLogger.ROOT_LOGGER.noArgValue(arg));
                        usage();
                        return null;
                    }
                    String value = idx > -1 ? arg.substring(idx + 1) : args[++i];
                    value = fixPossibleIPv6URL(value);
                    String propertyName = null;
                    if (idx < 0) {
                        // -b xxx -bmanagement xxx
                        propertyName = arg.length() == 2 ? org.jboss.as.server.ServerEnvironment.JBOSS_BIND_ADDRESS : org.jboss.as.server.ServerEnvironment.JBOSS_BIND_ADDRESS_PREFIX + arg.substring(2);
                    } else if (idx == 2) {
                        // -b=xxx
                        propertyName = org.jboss.as.server.ServerEnvironment.JBOSS_BIND_ADDRESS;
                    } else {
                        // -bmanagement=xxx
                        propertyName = org.jboss.as.server.ServerEnvironment.JBOSS_BIND_ADDRESS_PREFIX + arg.substring(2, idx);
                    }
                    systemProperties.setProperty(propertyName, value);
                } else if (arg.startsWith(CommandLineConstants.DEFAULT_MULTICAST_ADDRESS)) {

                    int idx = arg.indexOf('=');
                    if (idx == arg.length() - 1) {
                        System.err.println(ServerLogger.ROOT_LOGGER.valueExpectedForCommandLineOption(arg));
                        usage();
                        return null;
                    }
                    String value = idx > -1 ? arg.substring(idx + 1) : args[++i];
                    value = fixPossibleIPv6URL(value);

                    systemProperties.setProperty(org.jboss.as.server.ServerEnvironment.JBOSS_DEFAULT_MULTICAST_ADDRESS, value);
                } else if (arg.startsWith(CommandLineConstants.SECURITY_PROP)) {
                    //Value can be a comma separated key value pair
                    //Drop the first 2 characters
                    String token = arg.substring(2);
                    processSecurityProperties(token, systemProperties);
                } else if (arg.startsWith(CommandLineConstants.START_MODE)) {
                    int idx = arg.indexOf('=');
                    if (idx == arg.length() - 1) {
                        System.err.println(ServerLogger.ROOT_LOGGER.noArgValue(arg));
                        usage();
                        return null;
                    }
                    String value = idx > -1 ? arg.substring(idx + 1) : args[++i];
                    value = value.toLowerCase(Locale.ENGLISH);
                    switch (value) {
                        case CommandLineConstants.ADMIN_ONLY_MODE:
                            builder.setAdminMode(true);
                            break;
                        case CommandLineConstants.SUSPEND_MODE:
                            builder.setStartSuspended(true);
                            break;
                        case CommandLineConstants.NORMAL_MODE:
                            break;
                        default:
                            System.err.println(ServerLogger.ROOT_LOGGER.unknownStartMode(value));
                            usage();
                            return null;
                    }
                } else {
                    System.err.println(ServerLogger.ROOT_LOGGER.invalidCommandLineOption(arg));
                    usage();
                    return null;
                }
            } catch (IndexOutOfBoundsException e) {
                System.err.println(ServerLogger.ROOT_LOGGER.valueExpectedForCommandLineOption(arg));
                usage();
                return null;
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        }
        Path jbossHomeDir = getJBossHome(serverDir);
        long t = System.currentTimeMillis();
        try ( InputStream wf = Main.class.getResourceAsStream("/wildfly.zip")) {
            unzip(wf, jbossHomeDir.toFile());
        }

        configureLogging(jbossHomeDir);
        UberJarLogger.ROOT_LOGGER.advertiseInstall(jbossHomeDir, System.currentTimeMillis() - t);

        // Initialize Configuration, side effect is proper ModuleLoader configuration.
        Configuration.Builder configBuilder = Configuration.Builder.of(jbossHomeDir);
        Configuration config = configBuilder.build();
        builder.setConfig(config);
        if (serverDir == null) {
            builder.setTmpServerDir(jbossHomeDir);
        }

        if (isVersion) {
            ProductConfig productConfig = ProductConfig.fromFilesystemSlot(org.jboss.modules.Module.getBootModuleLoader(), jbossHomeDir.toAbsolutePath().toString(), null);
            System.out.println(productConfig.getPrettyVersionString());
            return null;
        } else {
            return builder.addProperties(systemProperties).build();
        }
    }

    private static void configureLogging(Path jbossHome) throws IOException {
        System.setProperty(LOG_MANAGER_PROP, LOG_MANAGER_CLASS);
        configureEmbeddedLogging(jbossHome);
    }

    private static void configureEmbeddedLogging(Path jbossHome) throws IOException {
        System.setProperty("org.wildfly.logging.embedded", "false");
        LogContext ctx = configureLogContext(jbossHome);
        LogContext.setLogContextSelector(() -> {
            return ctx;
        });
    }

    private static LogContext configureLogContext(Path jbossHome) throws IOException {
        final String baseDir = jbossHome.resolve("standalone").toAbsolutePath().toString();
        String serverLogDir = System.getProperty(JBOSS_SERVER_LOG_DIR, null);
        if (serverLogDir == null) {
            serverLogDir = baseDir + File.separator + "log";
            System.setProperty(JBOSS_SERVER_LOG_DIR, serverLogDir);
        }
        final String serverCfgDir = System.getProperty(JBOSS_SERVER_CONFIG_DIR, baseDir + File.separator + "configuration");
        final LogContext embeddedLogContext = LogContext.create();
        final Path bootLog = Paths.get(serverLogDir).resolve("server.log");
        final Path loggingProperties = Paths.get(serverCfgDir).resolve(Paths.get("logging.properties"));
        if (Files.exists(loggingProperties)) {
            try (final InputStream in = Files.newInputStream(loggingProperties)) {
                System.setProperty(LOG_BOOT_FILE_PROP, bootLog.toAbsolutePath().toString());
                PropertyConfigurator configurator = new PropertyConfigurator(embeddedLogContext);
                configurator.configure(in);
            }
        }
        return embeddedLogContext;
    }
    private static Path checkPath(String path) {
        Path filePath = Paths.get(path);
        if (!Files.exists(filePath)) {
            throw new RuntimeException("File " + path + " doesn't exist");
        }
        return filePath;
    }

    private static String getValue(String arg) {
        int sep = arg.indexOf("=");
        if (sep == -1 || sep == arg.length() - 1) {
            throw new RuntimeException("Invalid argument " + arg + ", no value provided");
        }
        return arg.substring(sep + 1);
    }

    private static void usage() {
        CmdUsage.printUsage(System.out);
    }

    private static String parseValue(final String arg, final String key) {
        String value = null;
        int splitPos = key.length();
        if (arg.length() <= splitPos + 1 || arg.charAt(splitPos) != '=') {
            usage();
        } else {
            value = arg.substring(splitPos + 1);
        }
        return value;
    }

    private static String fixPossibleIPv6URL(String val) {
        String result = val;
        if (val != null && val.length() > 2
                && val.charAt(0) == '[' && val.charAt(val.length() - 1) == ']'
                && val.contains(":")) {
            result = val.substring(1, val.length() - 1);
        }
        return result;
    }

    private static boolean processProperties(final String arg, final String urlSpec, Properties systemProperties) {
        URL url = null;
        try {
            url = makeURL(urlSpec);
            systemProperties.load(url.openConnection().getInputStream());
            return true;
        } catch (MalformedURLException e) {
            System.err.println(ServerLogger.ROOT_LOGGER.malformedCommandLineURL(urlSpec, arg));
            usage();
            return false;
        } catch (IOException e) {
            System.err.println(ServerLogger.ROOT_LOGGER.unableToLoadProperties(url));
            usage();
            return false;
        }
    }

    private static URL makeURL(String urlspec) throws MalformedURLException {
        urlspec = urlspec.trim();

        URL url;

        try {
            url = new URL(urlspec);
            if (url.getProtocol().equals("file")) {
                // make sure the file is absolute & canonical file url
                File file = new File(url.getFile()).getCanonicalFile();
                url = file.toURI().toURL();
            }
        } catch (Exception e) {
            // make sure we have an absolute & canonical file url
            try {
                File file = new File(urlspec).getCanonicalFile();
                url = file.toURI().toURL();
            } catch (Exception n) {
                throw new MalformedURLException(n.toString());
            }
        }

        return url;
    }

    private static void processSecurityProperties(String secProperties, Properties systemProperties) {
        StringTokenizer tokens = new StringTokenizer(secProperties, ",");
        while (tokens.hasMoreTokens()) {
            String token = tokens.nextToken();

            int idx = token.indexOf('=');
            if (idx == token.length() - 1) {
                System.err.println(ServerLogger.ROOT_LOGGER.valueExpectedForCommandLineOption(secProperties));
                usage();
                return;
            }
            String value = token.substring(idx + 1);
            String key = token.substring(0, idx);
            systemProperties.setProperty(key, value);
        }
    }

    private static Path getJBossHome(Path path) throws IOException {
        if (path != null) {
            if (Files.exists(path)) {
                throw new IOException("Installation directory " + path + " already exists");
            }
            Files.createDirectories(path);
        } else {
            path = Files.createTempDirectory("wildfly-uberjar-server");
        }
        return path;
    }

    private static void unzip(InputStream wf, File dir) throws Exception {
        byte[] buffer = new byte[1024];
        try ( ZipInputStream zis = new ZipInputStream(wf)) {
            ZipEntry ze = zis.getNextEntry();
            while (ze != null) {
                String fileName = ze.getName();
                File newFile = new File(dir, fileName);
                if (fileName.endsWith("/")) {
                    newFile.mkdirs();
                    zis.closeEntry();
                    ze = zis.getNextEntry();
                    continue;
                }
                try ( FileOutputStream fos = new FileOutputStream(newFile)) {
                    int len;
                    while ((len = zis.read(buffer)) > 0) {
                        fos.write(buffer, 0, len);
                    }
                }
                if (newFile.getName().endsWith(".sh")) {
                    Files.setPosixFilePermissions(newFile.toPath(), EXECUTE_PERMISSIONS);
                }
                zis.closeEntry();
                ze = zis.getNextEntry();
            }
        }
    }
}
