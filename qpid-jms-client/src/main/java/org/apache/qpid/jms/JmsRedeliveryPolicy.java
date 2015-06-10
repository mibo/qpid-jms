/**
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
package org.apache.qpid.jms;

/**
 * Defines the policy used to manage redelivered and recovered Messages.
 */
public class JmsRedeliveryPolicy {

    public static final int DEFAULT_MAX_REDELIVERIES = -1;

    private int maxRedeliveries;

    public JmsRedeliveryPolicy() {
        maxRedeliveries = DEFAULT_MAX_REDELIVERIES;
    }

    public JmsRedeliveryPolicy(JmsRedeliveryPolicy source) {
        maxRedeliveries = source.maxRedeliveries;
    }

    public JmsRedeliveryPolicy copy() {
        return new JmsRedeliveryPolicy(this);
    }

    /**
     * Returns the configured maximum redeliveries that a message will be
     * allowed to have before it is rejected by this client.
     *
     * @return the maxRedeliveries
     *         the maximum number of redeliveries allowed before a message is rejected.
     */
    public int getMaxRedeliveries() {
        return maxRedeliveries;
    }

    /**
     * Configures the maximum number of time a message can be redelivered before it
     * will be rejected by this client.
     *
     * The default value of (-1) disables max redelivery processing.
     *
     * @param maxRedeliveries the maxRedeliveries to set
     */
    public void setMaxRedeliveries(int maxRedeliveries) {
        this.maxRedeliveries = maxRedeliveries;
    }
}
