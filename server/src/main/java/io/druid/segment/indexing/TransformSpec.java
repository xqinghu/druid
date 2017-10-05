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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableList;
import io.druid.data.input.impl.InputRowParser;
import io.druid.data.input.impl.StringInputRowParser;
import io.druid.java.util.common.ISE;
import io.druid.query.filter.DimFilter;

import javax.annotation.Nullable;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public class TransformSpec
{
  public static final TransformSpec NONE = new TransformSpec(null, null);

  private final DimFilter filter;
  private final List<Transform> transforms;

  @JsonCreator
  public TransformSpec(
      @JsonProperty("filter") final DimFilter filter,
      @JsonProperty("transforms") final List<Transform> transforms
  )
  {
    this.filter = filter;
    this.transforms = transforms == null ? ImmutableList.of() : transforms;

    // Check for name collisions.
    final Set<String> seen = new HashSet<>();
    for (Transform transform : this.transforms) {
      if (!seen.add(transform.getName())) {
        throw new ISE("Transform name '%s' cannot be used twice", transform.getName());
      }
    }
  }

  public static <T> TransformSpec fromInputRowParser(final InputRowParser<T> parser)
  {
    // Hack: some firehoses and input specs must extract transformSpec from the parser, since they do not
    // actually use the parser. This method should extract whatever transformSpec "decorate" had put in.

    if (parser instanceof TransformingInputRowParser) {
      return ((TransformingInputRowParser) parser).getTransformSpec();
    } else if (parser instanceof TransformingStringInputRowParser) {
      return ((TransformingStringInputRowParser) parser).getTransformSpec();
    } else {
      return TransformSpec.NONE;
    }
  }

  @JsonProperty
  @Nullable
  public DimFilter getFilter()
  {
    return filter;
  }

  @JsonProperty
  public List<Transform> getTransforms()
  {
    return transforms;
  }

  public <T> InputRowParser<T> decorate(final InputRowParser<T> parser)
  {
    if (filter == null && transforms.isEmpty()) {
      return parser;
    } else if (parser instanceof StringInputRowParser) {
      // Hack to support the fact that some callers use special methods in StringInputRowParser, such as
      // parse(String) and startFileFromBeginning.
      return (InputRowParser<T>) new TransformingStringInputRowParser(
          parser.getParseSpec(),
          ((StringInputRowParser) parser).getEncoding(),
          this
      );
    } else {
      return new TransformingInputRowParser<>(parser, this);
    }
  }

  public Transformer toTransformer()
  {
    return new Transformer(this);
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
    final TransformSpec that = (TransformSpec) o;
    return Objects.equals(filter, that.filter) &&
           Objects.equals(transforms, that.transforms);
  }

  @Override
  public int hashCode()
  {
    return Objects.hash(filter, transforms);
  }

  @Override
  public String toString()
  {
    return "TransformSpec{" +
           "filter=" + filter +
           ", transforms=" + transforms +
           '}';
  }
}
