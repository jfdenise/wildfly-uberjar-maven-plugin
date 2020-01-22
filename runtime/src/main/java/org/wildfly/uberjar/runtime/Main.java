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

import org.wildfly.security.manager.WildFlySecurityManager;

/**
 *
 * @author jdenise
 */
public class Main {

    public static void main(String[] args) throws Exception {
        UberJarServerEnvironment env = UberJarServerEnvironment.buildEnvironment(args);
        if (env == null) {
            return;
        }
        for (String name : env.getSystemProperties().stringPropertyNames()) {
            WildFlySecurityManager.setPropertyPrivileged(name, env.getSystemProperties().getProperty(name));
        }
        UberJar uberjar = new UberJar(env);
        uberjar.run();
    }

}
