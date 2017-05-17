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
package io.druid.query.scan;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import io.druid.query.BaseQuery;
import io.druid.query.DataSource;
import io.druid.query.Query;
import io.druid.query.TableDataSource;
import io.druid.query.filter.DimFilter;
import io.druid.query.filter.InDimFilter;
import io.druid.query.filter.SelectorDimFilter;
import io.druid.query.spec.LegacySegmentSpec;
import io.druid.query.spec.QuerySegmentSpec;
import io.druid.segment.VirtualColumn;
import io.druid.segment.VirtualColumns;
import org.joda.time.Interval;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class ScanQuery extends BaseQuery<ScanResultValue>
{
  public static final String SCAN = "scan";
  public static final String RESULT_FORMAT_LIST = "list";
  public static final String RESULT_FORMAT_COMPACTED_LIST = "compactedList";
  public static final String RESULT_FORMAT_VALUE_VECTOR = "valueVector";

  private final VirtualColumns virtualColumns;
  private final String resultFormat;
  private final int batchSize;
  private final int limit;
  private final DimFilter dimFilter;
  private final List<String> columns;

  @JsonCreator
  public ScanQuery(
      @JsonProperty("dataSource") DataSource dataSource,
      @JsonProperty("intervals") QuerySegmentSpec querySegmentSpec,
      @JsonProperty("virtualColumns") VirtualColumns virtualColumns,
      @JsonProperty("resultFormat") String resultFormat,
      @JsonProperty("batchSize") int batchSize,
      @JsonProperty("limit") int limit,
      @JsonProperty("filter") DimFilter dimFilter,
      @JsonProperty("columns") List<String> columns,
      @JsonProperty("context") Map<String, Object> context
  )
  {
    super(dataSource, querySegmentSpec, false, context);
    this.virtualColumns = VirtualColumns.nullToEmpty(virtualColumns);
    this.resultFormat = resultFormat == null ? RESULT_FORMAT_LIST : resultFormat;
    this.batchSize = (batchSize == 0) ? 4096 * 5 : batchSize;
    this.limit = (limit == 0) ? Integer.MAX_VALUE : limit;
    Preconditions.checkArgument(this.batchSize > 0, "batchSize must be greater than 0");
    Preconditions.checkArgument(this.limit > 0, "limit must be greater than 0");
    this.dimFilter = dimFilter;
    this.columns = columns;
  }

  @JsonProperty
  public VirtualColumns getVirtualColumns()
  {
    return virtualColumns;
  }

  @JsonProperty
  public String getResultFormat()
  {
    return resultFormat;
  }

  @JsonProperty
  public int getBatchSize()
  {
    return batchSize;
  }

  @JsonProperty
  public int getLimit()
  {
    return limit;
  }

  @Override
  public boolean hasFilters()
  {
    return dimFilter != null;
  }

  @Override
  @JsonProperty
  public DimFilter getFilter()
  {
    return dimFilter;
  }

  @Override
  public String getType()
  {
    return SCAN;
  }

  @JsonProperty
  public List<String> getColumns()
  {
    return columns;
  }

  @Override
  public Query<ScanResultValue> withQuerySegmentSpec(QuerySegmentSpec querySegmentSpec)
  {
    return new ScanQuery(
        getDataSource(),
        querySegmentSpec,
        virtualColumns,
        resultFormat,
        batchSize,
        limit,
        dimFilter,
        columns,
        getContext()
    );
  }

  @Override
  public Query<ScanResultValue> withDataSource(DataSource dataSource)
  {
    return new ScanQuery(
        dataSource,
        getQuerySegmentSpec(),
        virtualColumns,
        resultFormat,
        batchSize,
        limit,
        dimFilter,
        columns,
        getContext()
    );
  }

  @Override
  public Query<ScanResultValue> withOverriddenContext(Map<String, Object> contextOverrides)
  {
    return new ScanQuery(
        getDataSource(),
        getQuerySegmentSpec(),
        virtualColumns,
        resultFormat,
        batchSize,
        limit,
        dimFilter,
        columns,
        computeOverridenContext(contextOverrides)
    );
  }

  public ScanQuery withDimFilter(DimFilter dimFilter)
  {
    return new ScanQuery(
        getDataSource(),
        getQuerySegmentSpec(),
        virtualColumns,
        resultFormat,
        batchSize,
        limit,
        dimFilter,
        columns,
        getContext()
    );
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
    if (!super.equals(o)) {
      return false;
    }
    final ScanQuery scanQuery = (ScanQuery) o;
    return batchSize == scanQuery.batchSize &&
           limit == scanQuery.limit &&
           Objects.equals(virtualColumns, scanQuery.virtualColumns) &&
           Objects.equals(resultFormat, scanQuery.resultFormat) &&
           Objects.equals(dimFilter, scanQuery.dimFilter) &&
           Objects.equals(columns, scanQuery.columns);
  }

  @Override
  public int hashCode()
  {
    return Objects.hash(super.hashCode(), virtualColumns, resultFormat, batchSize, limit, dimFilter, columns);
  }

  @Override
  public String toString()
  {
    return "ScanQuery{" +
           "dataSource='" + getDataSource() + '\'' +
           ", querySegmentSpec=" + getQuerySegmentSpec() +
           ", virtualColumns=" + virtualColumns +
           ", resultFormat='" + resultFormat + '\'' +
           ", batchSize=" + batchSize +
           ", limit=" + limit +
           ", dimFilter=" + dimFilter +
           ", columns=" + columns +
           '}';
  }

  /**
   * A Builder for ScanQuery.
   * <p/>
   * Required: dataSource(), intervals() must be called before build()
   * <p/>
   * Usage example:
   * <pre><code>
   *   ScanQuery query = new ScanQueryBuilder()
   *                                  .dataSource("Example")
   *                                  .interval("2010/2013")
   *                                  .build();
   * </code></pre>
   *
   * @see io.druid.query.scan.ScanQuery
   */
  public static class ScanQueryBuilder
  {
    private DataSource dataSource;
    private QuerySegmentSpec querySegmentSpec;
    private VirtualColumns virtualColumns;
    private Map<String, Object> context;
    private String resultFormat;
    private int batchSize;
    private int limit;
    private DimFilter dimFilter;
    private List<String> columns;

    public ScanQueryBuilder()
    {
      dataSource = null;
      querySegmentSpec = null;
      virtualColumns = null;
      context = null;
      resultFormat = null;
      batchSize = 0;
      limit = 0;
      dimFilter = null;
      columns = Lists.newArrayList();
    }

    public ScanQuery build()
    {
      return new ScanQuery(
          dataSource,
          querySegmentSpec,
          virtualColumns,
          resultFormat,
          batchSize,
          limit,
          dimFilter,
          columns,
          context
      );
    }

    public ScanQueryBuilder copy(ScanQueryBuilder builder)
    {
      return new ScanQueryBuilder()
          .dataSource(builder.dataSource)
          .intervals(builder.querySegmentSpec)
          .context(builder.context);
    }

    public ScanQueryBuilder dataSource(String ds)
    {
      dataSource = new TableDataSource(ds);
      return this;
    }

    public ScanQueryBuilder dataSource(DataSource ds)
    {
      dataSource = ds;
      return this;
    }

    public ScanQueryBuilder intervals(QuerySegmentSpec q)
    {
      querySegmentSpec = q;
      return this;
    }

    public ScanQueryBuilder intervals(String s)
    {
      querySegmentSpec = new LegacySegmentSpec(s);
      return this;
    }

    public ScanQueryBuilder intervals(List<Interval> l)
    {
      querySegmentSpec = new LegacySegmentSpec(l);
      return this;
    }

    public ScanQueryBuilder virtualColumns(VirtualColumns virtualColumns)
    {
      this.virtualColumns = virtualColumns;
      return this;
    }

    public ScanQueryBuilder virtualColumns(List<VirtualColumn> virtualColumns)
    {
      return virtualColumns(VirtualColumns.create(virtualColumns));
    }

    public ScanQueryBuilder virtualColumns(VirtualColumn... virtualColumns)
    {
      return virtualColumns(VirtualColumns.create(Arrays.asList(virtualColumns)));
    }

    public ScanQueryBuilder context(Map<String, Object> c)
    {
      context = c;
      return this;
    }

    public ScanQueryBuilder resultFormat(String r)
    {
      resultFormat = r;
      return this;
    }

    public ScanQueryBuilder batchSize(int b)
    {
      batchSize = b;
      return this;
    }

    public ScanQueryBuilder limit(int l)
    {
      limit = l;
      return this;
    }

    public ScanQueryBuilder filters(String dimensionName, String value)
    {
      dimFilter = new SelectorDimFilter(dimensionName, value, null);
      return this;
    }

    public ScanQueryBuilder filters(String dimensionName, String value, String... values)
    {
      dimFilter = new InDimFilter(dimensionName, Lists.asList(value, values), null);
      return this;
    }

    public ScanQueryBuilder filters(DimFilter f)
    {
      dimFilter = f;
      return this;
    }

    public ScanQueryBuilder columns(List<String> c)
    {
      columns = c;
      return this;
    }

    public ScanQueryBuilder columns(String... c)
    {
      columns = Arrays.asList(c);
      return this;
    }
  }

  public static ScanQueryBuilder newScanQueryBuilder()
  {
    return new ScanQueryBuilder();
  }
}