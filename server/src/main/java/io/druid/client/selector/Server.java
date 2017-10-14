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

package io.druid.client.selector;

import java.util.Comparator;

/**
 */
public interface Server
{
  Comparator<Server> HOST_COMPARATOR = new Comparator<Server>()
  {
    final Comparator<String> cmp = Comparator.nullsFirst(String::compareToIgnoreCase);

    @Override
    public int compare(Server o1, Server o2)
    {
      return cmp.compare(o1.getHost(), o2.getHost());
    }
  };

  public String getScheme();
  public String getHost();
  public String getAddress();
  public int getPort();
}
