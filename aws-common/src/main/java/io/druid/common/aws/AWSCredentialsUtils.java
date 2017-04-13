/*
 * Licensed to Metamarkets Group Inc. (Metamarkets) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. Metamarkets licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.druid.common.aws;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSCredentialsProviderChain;
import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;
import com.amazonaws.auth.InstanceProfileCredentialsProvider;
import com.amazonaws.auth.SystemPropertiesCredentialsProvider;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.metamx.common.logger.Logger;

import java.util.ArrayList;
import java.util.List;

public class AWSCredentialsUtils
{
  private static final Logger log = new Logger(AWSCredentialsUtils.class);

  public static AWSCredentialsProviderChain defaultAWSCredentialsProviderChain(final AWSCredentialsConfig config)
  {
    List<AWSCredentialsProvider> awsCredentialsProviders = new ArrayList<>();

    awsCredentialsProviders.add(new ConfigDrivenAwsCredentialsConfigProvider(config));
    awsCredentialsProviders.add(new LazyFileSessionCredentialsProvider(config));
    awsCredentialsProviders.add(new EnvironmentVariableCredentialsProvider());
    awsCredentialsProviders.add(new SystemPropertiesCredentialsProvider());

    try {
      awsCredentialsProviders.add(new ProfileCredentialsProvider());
    }
    catch (Exception e) {
      log.info(e.getMessage());
    }

    awsCredentialsProviders.add(new InstanceProfileCredentialsProvider());

    return new AWSCredentialsProviderChain(awsCredentialsProviders.toArray(new AWSCredentialsProvider[6]));
  }
}
