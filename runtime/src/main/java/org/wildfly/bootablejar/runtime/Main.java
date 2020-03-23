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
package org.wildfly.bootablejar.runtime;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.jboss.modules.Module;
import org.jboss.modules.ModuleClassLoader;
import org.jboss.modules.ModuleLoadException;
import org.jboss.modules.ModuleLoader;

/**
 *
 * @author jdenise
 */
public class Main {

    private static final String SYSPROP_KEY_CLASS_PATH = "java.class.path";
    private static final String SYSPROP_KEY_JBOSS_MODULES_DIR = "jboss.modules.dir";
    private static final String SYSPROP_KEY_LOGGING_PROVIDER = "org.jboss.logging.provider";
    private static final String SYSPROP_KEY_MODULE_PATH = "module.path";
    private static final String SYSPROP_KEY_SYSTEM_MODULES = "jboss.modules.system.pkgs";

    private static final String JBOSS_MODULES_DIR_NAME = "modules";

    private static final String MODULE_ID_JAR_RUNTIME = "org.wildfly.bootable-jar";
    private static final String MODULE_ID_VFS = "org.jboss.vfs";
    private static final String BOOTABLE_JAR_FACTORY = "org.wildfly.bootablejar.runtime.BootableJar2";
    private static final String BOOTABLE_JAR_FACTORY2 = "org.wildfly.bootablejar.runtime.Test1";
    static final String[] EXTENDED_SYSTEM_PKGS = new String[]{"org.jboss.logging", "org.jboss.logmanager"};

    public static void main(String[] args) throws Exception {
        Arguments arguments;
        try {
            arguments = Arguments.parseArguments(args);
        } catch (Throwable ex) {
            System.err.println(ex);
            CmdUsage.printUsage(System.out);
            return;
        }
        if (arguments.isHelp()) {
            CmdUsage.printUsage(System.out);
        } else {
            Path jbossHome = arguments.installDir() == null ? Files.createTempDirectory("wildfly-bootable-server") : arguments.installDir();

            long t = System.currentTimeMillis();
            try (InputStream wf = Main.class.getResourceAsStream("/wildfly.zip")) {
                unzip(wf, jbossHome.toFile());
            }
            final String modulePath = jbossHome.resolve(JBOSS_MODULES_DIR_NAME).toAbsolutePath().toString();
            ModuleLoader moduleLoader = setupModuleLoader(modulePath);
            //setupVfsModule(moduleLoader);
            // Load the Embedded Server Module
            final Module bjModule;
            try {
                bjModule = moduleLoader.loadModule(MODULE_ID_JAR_RUNTIME);
            } catch (final ModuleLoadException mle) {
                throw new Exception(mle);
            }

            // Load the Embedded Server Factory via the modular environment
            final ModuleClassLoader bjModuleCL = bjModule.getClassLoader();
            final Class<?> bjFactoryClass;
            try {
                bjFactoryClass = bjModuleCL.loadClass(BOOTABLE_JAR_FACTORY);
            } catch (final ClassNotFoundException cnfe) {
                throw new Exception(cnfe);
            }
            Method runBjMethod;
            try {
                //runBjMethod = bjFactoryClass.getMethod("doIt");
                runBjMethod = bjFactoryClass.getMethod("run", List.class, Path.class, Path.class, ModuleLoader.class, Boolean.class);
            } catch (final NoSuchMethodException nsme) {
                throw new Exception(nsme);
            }
            runBjMethod.invoke(null, arguments.getServerArguments(), arguments.getDeployment(), jbossHome, moduleLoader, arguments.isVersion());
            //runBjMethod.invoke(null, jbossHome, moduleLoader);
            //runBjMethod.invoke(null);
        }
    }

//    private static void setupVfsModule(final ModuleLoader moduleLoader) throws Exception {
//        final ModuleIdentifier vfsModuleID = ModuleIdentifier.create(MODULE_ID_VFS);
//        final Module vfsModule;
//        try {
//            vfsModule = moduleLoader.loadModule(vfsModuleID);
//        } catch (final ModuleLoadException mle) {
//            throw new Exception(mle);
//        }
//        Module.registerURLStreamHandlerFactoryModule(vfsModule);
//    }

    private static void unzip(InputStream wf, File dir) throws Exception {
        byte[] buffer = new byte[1024];
        try (ZipInputStream zis = new ZipInputStream(wf)) {
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
                try (FileOutputStream fos = new FileOutputStream(newFile)) {
                    int len;
                    while ((len = zis.read(buffer)) > 0) {
                        fos.write(buffer, 0, len);
                    }
                }
                zis.closeEntry();
                ze = zis.getNextEntry();
            }
        }
    }

    private static String trimPathToModulesDir(String modulePath) {
        int index = modulePath.indexOf(File.pathSeparator);
        return index == -1 ? modulePath : modulePath.substring(0, index);
    }

    private static ModuleLoader setupModuleLoader(final String modulePath, final String... systemPackages) {
        System.out.println("SETUP MODULELOADER");
        assert modulePath != null : "modulePath not null";

        // verify the the first element of the supplied modules path exists, and if it does not, stop and allow the user to correct.
        // Once modules are initialized and loaded we can't change Module.BOOT_MODULE_LOADER (yet).
        final Path moduleDir = Paths.get(trimPathToModulesDir(modulePath));
        if (Files.notExists(moduleDir) || !Files.isDirectory(moduleDir)) {
            throw new RuntimeException("The first directory of the specified module path " + modulePath + " is invalid or does not exist.");
        }

        // deprecated property
        SecurityActions.setPropertyPrivileged(SYSPROP_KEY_JBOSS_MODULES_DIR, moduleDir.toAbsolutePath().toString());

        final String classPath = SecurityActions.getPropertyPrivileged(SYSPROP_KEY_CLASS_PATH);
        try {
            // Set up sysprop env
            SecurityActions.clearPropertyPrivileged(SYSPROP_KEY_CLASS_PATH);
            SecurityActions.setPropertyPrivileged(SYSPROP_KEY_MODULE_PATH, modulePath);

            final StringBuilder packages = new StringBuilder("org.jboss.modules,org.jboss.logging,org.jboss.logmanager");
            if (systemPackages != null) {
                for (String packageName : systemPackages) {
                    packages.append(",");
                    packages.append(packageName);
                }
            }
            SecurityActions.setPropertyPrivileged(SYSPROP_KEY_SYSTEM_MODULES, packages.toString());

            // Get the module loader
            return Module.getBootModuleLoader();
        } finally {
            // Return to previous state for classpath prop
            if (classPath != null) {
                SecurityActions.setPropertyPrivileged(SYSPROP_KEY_CLASS_PATH, classPath);
            }
        }
    }
}
