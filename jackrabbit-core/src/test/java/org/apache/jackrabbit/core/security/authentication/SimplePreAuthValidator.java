/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.jackrabbit.core.security.authentication;

import javax.jcr.Credentials;
import javax.jcr.SimpleCredentials;
import java.util.Map;

/**
 * User: chetanm
 * Date: 4/24/12
 * Time: 3:01 PM
 */
public class SimplePreAuthValidator implements PreAuthValidator {
    private static String secret;
    private static Map passedOptions;

    public void init(Map<String, ?> options) {
        passedOptions = options;
    }

    public boolean isPreAuthenticated(Credentials creds) {
        return (creds instanceof SimpleCredentials)
                           && ((SimpleCredentials) creds).getAttribute(secret) != null;
    }

    public static void reset(){
        secret = null;
        passedOptions = null;
    }

    public static void setSecret(String secret) {
        SimplePreAuthValidator.secret = secret;
    }

    public static Map getPassedOptions() {
        return passedOptions;
    }
}
