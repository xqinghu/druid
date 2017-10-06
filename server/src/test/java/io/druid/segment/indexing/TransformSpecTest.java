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

package io.druid.segment.indexing;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import io.druid.data.input.InputRow;
import io.druid.data.input.impl.DimensionsSpec;
import io.druid.data.input.impl.InputRowParser;
import io.druid.data.input.impl.MapInputRowParser;
import io.druid.data.input.impl.TimeAndDimsParseSpec;
import io.druid.data.input.impl.TimestampSpec;
import io.druid.java.util.common.DateTimes;
import io.druid.query.expression.TestExprMacroTable;
import io.druid.query.filter.AndDimFilter;
import io.druid.query.filter.SelectorDimFilter;
import org.junit.Assert;
import org.junit.Test;

import java.util.Map;

public class TransformSpecTest
{
  private static final MapInputRowParser PARSER = new MapInputRowParser(
      new TimeAndDimsParseSpec(
          new TimestampSpec("t", "auto", DateTimes.of("2000-01-01")),
          new DimensionsSpec(
              DimensionsSpec.getDefaultSchemas(ImmutableList.of("f", "x", "y")),
              null,
              null
          )
      )
  );

  private static final Map<String, Object> ROW1 = ImmutableMap.<String, Object>builder()
      .put("x", "foo")
      .put("y", "bar")
      .put("a", 2.0)
      .put("b", 3L)
      .build();

  private static final Map<String, Object> ROW2 = ImmutableMap.<String, Object>builder()
      .put("x", "foo")
      .put("y", "baz")
      .put("a", 2.0)
      .put("b", 4L)
      .build();

  @Test
  public void testTransforms()
  {
    final TransformSpec transformSpec = new TransformSpec(
        null,
        ImmutableList.of(
            new Transform("f", "concat(x,y)", TestExprMacroTable.INSTANCE),
            new Transform("g", "a + b", TestExprMacroTable.INSTANCE),
            new Transform("h", "concat(f,g)", TestExprMacroTable.INSTANCE)
        )
    );

    final InputRowParser<Map<String, Object>> parser = transformSpec.decorate(PARSER);
    final InputRow row = parser.parse(ROW1);

    Assert.assertNotNull(row);
    Assert.assertEquals(DateTimes.of("2000-01-01").getMillis(), row.getTimestampFromEpoch());
    Assert.assertEquals(DateTimes.of("2000-01-01"), row.getTimestamp());
    Assert.assertEquals(ImmutableList.of("f", "x", "y"), row.getDimensions());
    Assert.assertEquals(ImmutableList.of("foo"), row.getDimension("x"));
    Assert.assertEquals(3.0, row.getDoubleMetric("b"), 0);
    Assert.assertEquals("foobar", row.getRaw("f"));
    Assert.assertEquals(ImmutableList.of("foobar"), row.getDimension("f"));
    Assert.assertEquals(ImmutableList.of("5.0"), row.getDimension("g"));
    Assert.assertEquals(ImmutableList.of(), row.getDimension("h"));
    Assert.assertEquals(0L, row.getLongMetric("f"));
    Assert.assertEquals(5L, row.getLongMetric("g"));
  }

  @Test
  public void testFilterOnTransforms()
  {
    final TransformSpec transformSpec = new TransformSpec(
        new AndDimFilter(
            ImmutableList.of(
                new SelectorDimFilter("x", "foo", null),
                new SelectorDimFilter("f", "foobar", null),
                new SelectorDimFilter("g", "5.0", null)
            )
        ),
        ImmutableList.of(
            new Transform("f", "concat(x,y)", TestExprMacroTable.INSTANCE),
            new Transform("g", "a + b", TestExprMacroTable.INSTANCE)
        )
    );

    final InputRowParser<Map<String, Object>> parser = transformSpec.decorate(PARSER);
    Assert.assertNotNull(parser.parse(ROW1));
    Assert.assertNull(parser.parse(ROW2));
  }

  @Test
  public void testTransformTimeFromOtherFields()
  {
    final TransformSpec transformSpec = new TransformSpec(
        null,
        ImmutableList.of(
            new Transform("__time", "(a + b) * 3600000", TestExprMacroTable.INSTANCE)
        )
    );

    final InputRowParser<Map<String, Object>> parser = transformSpec.decorate(PARSER);
    final InputRow row = parser.parse(ROW1);

    Assert.assertNotNull(row);
    Assert.assertEquals(DateTimes.of("1970-01-01T05:00:00Z"), row.getTimestamp());
    Assert.assertEquals(DateTimes.of("1970-01-01T05:00:00Z").getMillis(), row.getTimestampFromEpoch());
  }

  @Test
  public void testTransformTimeFromTime()
  {
    final TransformSpec transformSpec = new TransformSpec(
        null,
        ImmutableList.of(
            new Transform("__time", "__time + 3600000", TestExprMacroTable.INSTANCE)
        )
    );

    final InputRowParser<Map<String, Object>> parser = transformSpec.decorate(PARSER);
    final InputRow row = parser.parse(ROW1);

    Assert.assertNotNull(row);
    Assert.assertEquals(DateTimes.of("2000-01-01T01:00:00Z"), row.getTimestamp());
    Assert.assertEquals(DateTimes.of("2000-01-01T01:00:00Z").getMillis(), row.getTimestampFromEpoch());
  }
}