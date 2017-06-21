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

import com.google.common.base.Function;
import com.google.common.base.Strings;
import com.google.common.collect.Iterables;
import com.google.common.collect.Maps;
import com.google.common.primitives.Doubles;
import com.google.common.primitives.Ints;
import io.druid.client.DirectDruidClient;
import io.druid.common.guava.GuavaUtils;
import io.druid.data.input.Row;
import io.druid.java.util.common.ISE;
import io.druid.java.util.common.guava.Sequence;
import io.druid.java.util.common.guava.Sequences;
import io.druid.math.expr.Evals;
import io.druid.query.DataSource;
import io.druid.query.QueryDataSource;
import io.druid.query.QueryPlus;
import io.druid.query.QuerySegmentWalker;
import io.druid.query.Result;
import io.druid.query.groupby.GroupByQuery;
import io.druid.query.scan.ScanQuery;
import io.druid.query.timeseries.TimeseriesQuery;
import io.druid.query.timeseries.TimeseriesResultValue;
import io.druid.query.topn.DimensionAndMetricValueExtractor;
import io.druid.query.topn.TopNQuery;
import io.druid.query.topn.TopNResultValue;
import io.druid.server.initialization.ServerConfig;
import io.druid.sql.calcite.planner.Calcites;
import io.druid.sql.calcite.planner.PlannerContext;
import io.druid.sql.calcite.table.RowSignature;
import org.apache.calcite.avatica.ColumnMetaData;
import org.apache.calcite.rel.type.RelDataTypeField;
import org.apache.calcite.runtime.Hook;
import org.apache.calcite.sql.type.SqlTypeName;
import org.apache.calcite.util.NlsString;
import org.joda.time.DateTime;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class QueryMaker
{
  private final QuerySegmentWalker walker;
  private final PlannerContext plannerContext;
  private final ServerConfig serverConfig;

  public QueryMaker(
      final QuerySegmentWalker walker,
      final PlannerContext plannerContext,
      final ServerConfig serverConfig
  )
  {
    this.walker = walker;
    this.plannerContext = plannerContext;
    this.serverConfig = serverConfig;
  }

  public PlannerContext getPlannerContext()
  {
    return plannerContext;
  }

  public Sequence<Object[]> runQuery(
      final DataSource dataSource,
      final RowSignature sourceRowSignature,
      final DruidQueryBuilder queryBuilder
  )
  {
    if (dataSource instanceof QueryDataSource) {
      final GroupByQuery outerQuery = queryBuilder.toGroupByQuery(dataSource, plannerContext);
      if (outerQuery == null) {
        // Bug in the planner rules. They shouldn't allow this to happen.
        throw new IllegalStateException("Can't use QueryDataSource without an outer groupBy query!");
      }

      return executeGroupBy(queryBuilder, outerQuery);
    }

    final TimeseriesQuery tsQuery = queryBuilder.toTimeseriesQuery(dataSource, plannerContext);
    if (tsQuery != null) {
      return executeTimeseries(queryBuilder, tsQuery);
    }

    final TopNQuery topNQuery = queryBuilder.toTopNQuery(dataSource, plannerContext);
    if (topNQuery != null) {
      return executeTopN(queryBuilder, topNQuery);
    }

    final GroupByQuery groupByQuery = queryBuilder.toGroupByQuery(dataSource, plannerContext);
    if (groupByQuery != null) {
      return executeGroupBy(queryBuilder, groupByQuery);
    }

    final ScanQuery scanQuery = queryBuilder.toScanQuery(dataSource, plannerContext);
    if (scanQuery != null) {
      return executeScan(queryBuilder, scanQuery);
    }

    throw new IllegalStateException("WTF?! Cannot execute query even though we planned it?");
  }

  private Sequence<Object[]> executeScan(
      final DruidQueryBuilder queryBuilder,
      final ScanQuery baseQuery
  )
  {
    final ScanQuery query = DirectDruidClient.withDefaultTimeoutAndMaxScatterGatherBytes(
        baseQuery,
        serverConfig
    );

    final List<RelDataTypeField> fieldList = queryBuilder.getRowType().getFieldList();

    Hook.QUERY_PLAN.run(query);

    // SQL row column index -> Scan query column index
    final int[] columnMapping = new int[queryBuilder.getRowOrder().size()];

    final Map<String, Integer> scanColumnOrder = Maps.newHashMap();
    for (int i = 0; i < query.getColumns().size(); i++) {
      scanColumnOrder.put(query.getColumns().get(i), i);
    }
    for (int i = 0; i < queryBuilder.getRowOrder().size(); i++) {
      columnMapping[i] = scanColumnOrder.get(queryBuilder.getRowOrder().get(i));
    }

    return Sequences.concat(
        Sequences.map(
            query.run(
                walker,
                DirectDruidClient.makeResponseContextForQuery(query, plannerContext.getQueryStartTimeMillis())
            ),
            scanResult -> {
              final List<Object[]> retVals = new ArrayList<>();
              final List<List<Object>> rows = (List<List<Object>>) scanResult.getEvents();

              for (List<Object> row : rows) {
                final Object[] retVal = new Object[fieldList.size()];
                for (RelDataTypeField field : fieldList) {
                  retVal[field.getIndex()] = coerce(
                      row.get(columnMapping[field.getIndex()]),
                      field.getType().getSqlTypeName()
                  );
                }
                retVals.add(retVal);
              }

              return Sequences.simple(retVals);
            }
        )
    );
  }

  private Sequence<Object[]> executeTimeseries(
      final DruidQueryBuilder queryBuilder,
      final TimeseriesQuery baseQuery
  )
  {
    final TimeseriesQuery query = DirectDruidClient.withDefaultTimeoutAndMaxScatterGatherBytes(
        baseQuery,
        serverConfig
    );

    final List<RelDataTypeField> fieldList = queryBuilder.getRowType().getFieldList();
    final String timeOutputName = queryBuilder.getGrouping().getDimensions().isEmpty()
                                  ? null
                                  : Iterables.getOnlyElement(queryBuilder.getGrouping().getDimensions())
                                             .getOutputName();

    Hook.QUERY_PLAN.run(query);

    return Sequences.map(
        QueryPlus.wrap(query)
                 .run(
                     walker,
                     DirectDruidClient.makeResponseContextForQuery(query, plannerContext.getQueryStartTimeMillis())
                 ),
        new Function<Result<TimeseriesResultValue>, Object[]>()
        {
          @Override
          public Object[] apply(final Result<TimeseriesResultValue> result)
          {
            final Map<String, Object> row = result.getValue().getBaseObject();
            final Object[] retVal = new Object[fieldList.size()];

            for (final RelDataTypeField field : fieldList) {
              final String outputName = queryBuilder.getRowOrder().get(field.getIndex());
              if (outputName.equals(timeOutputName)) {
                retVal[field.getIndex()] = coerce(result.getTimestamp(), field.getType().getSqlTypeName());
              } else {
                retVal[field.getIndex()] = coerce(row.get(outputName), field.getType().getSqlTypeName());
              }
            }

            return retVal;
          }
        }
    );
  }

  private Sequence<Object[]> executeTopN(
      final DruidQueryBuilder queryBuilder,
      final TopNQuery baseQuery
  )
  {
    final TopNQuery query = DirectDruidClient.withDefaultTimeoutAndMaxScatterGatherBytes(
        baseQuery,
        serverConfig
    );

    final List<RelDataTypeField> fieldList = queryBuilder.getRowType().getFieldList();

    Hook.QUERY_PLAN.run(query);

    return Sequences.concat(
        Sequences.map(
            QueryPlus.wrap(query)
                     .run(
                         walker,
                         DirectDruidClient.makeResponseContextForQuery(query, plannerContext.getQueryStartTimeMillis())
                     ),
            new Function<Result<TopNResultValue>, Sequence<Object[]>>()
            {
              @Override
              public Sequence<Object[]> apply(final Result<TopNResultValue> result)
              {
                final List<DimensionAndMetricValueExtractor> rows = result.getValue().getValue();
                final List<Object[]> retVals = new ArrayList<>(rows.size());

                for (DimensionAndMetricValueExtractor row : rows) {
                  final Object[] retVal = new Object[fieldList.size()];
                  for (final RelDataTypeField field : fieldList) {
                    final String outputName = queryBuilder.getRowOrder().get(field.getIndex());
                    retVal[field.getIndex()] = coerce(row.getMetric(outputName), field.getType().getSqlTypeName());
                  }

                  retVals.add(retVal);
                }

                return Sequences.simple(retVals);
              }
            }
        )
    );
  }

  private Sequence<Object[]> executeGroupBy(
      final DruidQueryBuilder queryBuilder,
      final GroupByQuery baseQuery
  )
  {
    final GroupByQuery query = DirectDruidClient.withDefaultTimeoutAndMaxScatterGatherBytes(
        baseQuery,
        serverConfig
    );

    final List<RelDataTypeField> fieldList = queryBuilder.getRowType().getFieldList();

    Hook.QUERY_PLAN.run(query);
    return Sequences.map(
        QueryPlus.wrap(query)
                 .run(
                     walker,
                     DirectDruidClient.makeResponseContextForQuery(query, plannerContext.getQueryStartTimeMillis())
                 ),
        new Function<Row, Object[]>()
        {
          @Override
          public Object[] apply(final Row row)
          {
            final Object[] retVal = new Object[fieldList.size()];
            for (RelDataTypeField field : fieldList) {
              retVal[field.getIndex()] = coerce(
                  row.getRaw(queryBuilder.getRowOrder().get(field.getIndex())),
                  field.getType().getSqlTypeName()
              );
            }
            return retVal;
          }
        }
    );
  }

  public static ColumnMetaData.Rep rep(final SqlTypeName sqlType)
  {
    if (SqlTypeName.CHAR_TYPES.contains(sqlType)) {
      return ColumnMetaData.Rep.of(String.class);
    } else if (sqlType == SqlTypeName.TIMESTAMP) {
      return ColumnMetaData.Rep.of(Long.class);
    } else if (sqlType == SqlTypeName.DATE) {
      return ColumnMetaData.Rep.of(Integer.class);
    } else if (sqlType == SqlTypeName.INTEGER) {
      return ColumnMetaData.Rep.of(Integer.class);
    } else if (sqlType == SqlTypeName.BIGINT) {
      return ColumnMetaData.Rep.of(Long.class);
    } else if (sqlType == SqlTypeName.FLOAT || sqlType == SqlTypeName.DOUBLE || sqlType == SqlTypeName.DECIMAL) {
      return ColumnMetaData.Rep.of(Double.class);
    } else if (sqlType == SqlTypeName.OTHER) {
      return ColumnMetaData.Rep.of(Object.class);
    } else {
      throw new ISE("No rep for SQL type[%s]", sqlType);
    }
  }

  private Object coerce(final Object value, final SqlTypeName sqlType)
  {
    final Object coercedValue;

    if (SqlTypeName.CHAR_TYPES.contains(sqlType)) {
      if (value == null || value instanceof String) {
        coercedValue = Strings.nullToEmpty((String) value);
      } else if (value instanceof NlsString) {
        coercedValue = ((NlsString) value).getValue();
      } else if (value instanceof Number) {
        coercedValue = String.valueOf(value);
      } else {
        throw new ISE("Cannot coerce[%s] to %s", value.getClass().getName(), sqlType);
      }
    } else if (value == null) {
      coercedValue = null;
    } else if (sqlType == SqlTypeName.DATE) {
      final DateTime dateTime;

      if (value instanceof Number) {
        dateTime = new DateTime(((Number) value).longValue());
      } else if (value instanceof String) {
        dateTime = new DateTime(Long.parseLong((String) value));
      } else if (value instanceof DateTime) {
        dateTime = (DateTime) value;
      } else {
        throw new ISE("Cannot coerce[%s] to %s", value.getClass().getName(), sqlType);
      }

      return Calcites.jodaToCalciteDate(dateTime, plannerContext.getTimeZone());
    } else if (sqlType == SqlTypeName.TIMESTAMP) {
      final DateTime dateTime;

      if (value instanceof Number) {
        dateTime = new DateTime(((Number) value).longValue());
      } else if (value instanceof String) {
        dateTime = new DateTime(Long.parseLong((String) value));
      } else if (value instanceof DateTime) {
        dateTime = (DateTime) value;
      } else {
        throw new ISE("Cannot coerce[%s] to %s", value.getClass().getName(), sqlType);
      }

      return Calcites.jodaToCalciteTimestamp(dateTime, plannerContext.getTimeZone());
    } else if (sqlType == SqlTypeName.BOOLEAN) {
      if (value instanceof String) {
        coercedValue = Evals.asBoolean(((String) value));
      } else if (value instanceof Number) {
        coercedValue = Evals.asBoolean(((Number) value).longValue());
      } else {
        throw new ISE("Cannot coerce[%s] to %s", value.getClass().getName(), sqlType);
      }
    } else if (sqlType == SqlTypeName.INTEGER) {
      if (value instanceof String) {
        coercedValue = Ints.tryParse((String) value);
      } else if (value instanceof Number) {
        coercedValue = ((Number) value).intValue();
      } else {
        throw new ISE("Cannot coerce[%s] to %s", value.getClass().getName(), sqlType);
      }
    } else if (sqlType == SqlTypeName.BIGINT) {
      if (value instanceof String) {
        coercedValue = GuavaUtils.tryParseLong((String) value);
      } else if (value instanceof Number) {
        coercedValue = ((Number) value).longValue();
      } else {
        throw new ISE("Cannot coerce[%s] to %s", value.getClass().getName(), sqlType);
      }
    } else if (sqlType == SqlTypeName.FLOAT || sqlType == SqlTypeName.DOUBLE || sqlType == SqlTypeName.DECIMAL) {
      if (value instanceof String) {
        coercedValue = Doubles.tryParse((String) value);
      } else if (value instanceof Number) {
        coercedValue = ((Number) value).doubleValue();
      } else {
        throw new ISE("Cannot coerce[%s] to %s", value.getClass().getName(), sqlType);
      }
    } else if (sqlType == SqlTypeName.OTHER) {
      // Complex type got out somehow.
      coercedValue = value.getClass().getName();
    } else {
      throw new ISE("Cannot coerce[%s] to %s", value.getClass().getName(), sqlType);
    }

    return coercedValue;
  }
}
