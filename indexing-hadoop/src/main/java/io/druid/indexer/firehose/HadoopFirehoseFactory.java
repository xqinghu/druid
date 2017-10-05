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

package io.druid.indexer.firehose;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Preconditions;
import io.druid.data.input.Firehose;
import io.druid.data.input.FirehoseFactory;
import io.druid.data.input.impl.InputRowParser;
import io.druid.java.util.common.ISE;
import io.druid.java.util.common.parsers.ParseException;
import org.apache.hadoop.mapreduce.InputFormat;

import java.io.File;
import java.io.IOException;

public class HadoopFirehoseFactory implements FirehoseFactory<InputRowParser>
{
  private final String inputFormatClass;

  @JsonCreator
  public HadoopFirehoseFactory(
      @JsonProperty("inputFormatClass") final String inputFormatClass
  )
  {
    this.inputFormatClass = Preconditions.checkNotNull(inputFormatClass, "inputFormatClass");
  }

  @Override
  public Firehose connect(
      final InputRowParser parser,
      final File temporaryDirectory
  ) throws IOException, ParseException
  {
    try {
      final Class<?> clazz = Class.forName(inputFormatClass);
      if (!InputFormat.class.isAssignableFrom(clazz)) {
        throw new ISE("inputFormatClass[%s] is not a[%s]", InputFormat.class.getName());
      }

      final InputFormat inputFormat = (InputFormat) clazz.newInstance();
      
    }
    catch (ClassNotFoundException e) {
      throw new ISE(e, "inputFormatClass[%s] not found", inputFormatClass);
    }
    catch (InstantiationException | IllegalAccessException e) {
      throw new ISE(e, "inputFormatClass[%s] could not be constructed");
    }
  }
}
