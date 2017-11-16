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

package io.druid.security.basic.authentication.db.updater;

import io.druid.security.basic.authentication.entity.BasicAuthenticatorUser;

import java.util.Map;

public class NoopBasicAuthenticatorMetadataStorageUpdater implements BasicAuthenticatorMetadataStorageUpdater
{
  @Override
  public void createUser(String prefix, String userName)
  {
    throw new UnsupportedOperationException("not supported");
  }

  @Override
  public void deleteUser(String prefix, String userName)
  {
    throw new UnsupportedOperationException("not supported");

  }

  @Override
  public void setUserCredentials(String prefix, String userName, char[] password)
  {
    throw new UnsupportedOperationException("not supported");

  }

  @Override
  public Map<String, BasicAuthenticatorUser> getCachedUserMap(String prefix)
  {
    throw new UnsupportedOperationException("not supported");
  }

  @Override
  public byte[] getCachedSerializedUserMap(String prefix)
  {
    throw new UnsupportedOperationException("not supported");
  }

  @Override
  public byte[] getCurrentUserMapBytes(String prefix)
  {
    throw new UnsupportedOperationException("not supported");
  }

  @Override
  public Map<String, BasicAuthenticatorUser> deserializeUserMap(byte[] userMapBytes)
  {
    throw new UnsupportedOperationException("not supported");
  }

  @Override
  public byte[] serializeUserMap(Map<String, BasicAuthenticatorUser> userMap)
  {
    throw new UnsupportedOperationException("not supported");
  }
}