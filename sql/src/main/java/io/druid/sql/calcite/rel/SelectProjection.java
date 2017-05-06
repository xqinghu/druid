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

package io.druid.sql.calcite.rel;

import io.druid.segment.VirtualColumns;
import org.apache.calcite.rel.core.Project;

import java.util.Objects;

public class SelectProjection
{
  private final Project project;
  private final VirtualColumns virtualColumns;

  public SelectProjection(
      final Project project,
      final VirtualColumns virtualColumns
  )
  {
    this.project = project;
    this.virtualColumns = virtualColumns;
  }

  public Project getProject()
  {
    return project;
  }

  public VirtualColumns getVirtualColumns()
  {
    return virtualColumns;
  }

  @Override
  public boolean equals(final Object o)
  {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    final SelectProjection that = (SelectProjection) o;
    return Objects.equals(project, that.project) &&
           Objects.equals(virtualColumns, that.virtualColumns);
  }

  @Override
  public int hashCode()
  {
    return Objects.hash(project, virtualColumns);
  }

  @Override
  public String toString()
  {
    return "SelectProjection{" +
           "project=" + project +
           ", virtualColumns=" + virtualColumns +
           '}';
  }
}
