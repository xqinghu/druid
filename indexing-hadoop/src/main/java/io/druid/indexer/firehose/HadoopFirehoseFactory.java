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
import com.google.common.collect.ImmutableMap;
import io.druid.data.input.Firehose;
import io.druid.data.input.FirehoseFactory;
import io.druid.data.input.InputRow;
import io.druid.data.input.impl.InputRowParser;
import io.druid.java.util.common.ISE;
import io.druid.java.util.common.logger.Logger;
import io.druid.java.util.common.parsers.ParseException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.mapreduce.InputFormat;
import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.JobContext;
import org.apache.hadoop.mapreduce.JobID;
import org.apache.hadoop.mapreduce.RecordReader;
import org.apache.hadoop.mapreduce.task.JobContextImpl;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

public class HadoopFirehoseFactory implements FirehoseFactory<InputRowParser>
{
  private static final Logger log = new Logger(HadoopFirehoseFactory.class);

  private final String inputFormatClass;
  private final Map<String, String> properties;

  @JsonCreator
  public HadoopFirehoseFactory(
      @JsonProperty("inputFormatClass") final String inputFormatClass,
      @JsonProperty("properties") final Map<String, String> properties
  )
  {
    this.inputFormatClass = Preconditions.checkNotNull(inputFormatClass, "inputFormatClass");
    this.properties = properties != null ? properties : ImmutableMap.of();
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

      final InputFormat<?, ?> inputFormat = (InputFormat<?, ?>) clazz.newInstance();
      final Configuration configuration = new Configuration();
      properties.forEach(configuration::set);
      final JobContext jobContext = new JobContextImpl(configuration, new JobID("local", 0));
      final List<InputSplit> splits = inputFormat.getSplits(jobContext);

      log.info("Connected with splits: %s", splits);
      return new HadoopFirehose(parser, inputFormat, splits);
    }
    catch (ClassNotFoundException e) {
      throw new ISE(e, "inputFormatClass[%s] not found", inputFormatClass);
    }
    catch (InstantiationException | IllegalAccessException e) {
      throw new ISE(e, "inputFormatClass[%s] could not be constructed");
    }
    catch (InterruptedException e) {
      throw new RuntimeException(e);
    }
  }

  static class HadoopFirehose implements Firehose
  {
    private final InputRowParser<?> parser;
    private final InputFormat<?, ?> inputFormat;
    private final List<InputSplit> splits;

    private int nextSplit = 0;
    private RecordReader<?, ?> currentRecordReader = null;

    public HadoopFirehose(
        final InputRowParser<?> parser,
        final InputFormat<?, ?> inputFormat,
        final List<InputSplit> splits
    )
    {
      this.parser = parser;
      this.inputFormat = inputFormat;
      this.splits = splits;
    }

    @Override
    public boolean hasMore()
    {
      return nextSplit < splits.size();
    }

    @Nullable
    @Override
    public InputRow nextRow()
    {
      if (currentRecordReader == null) {
        
      }
    }

    @Override
    public Runnable commit()
    {
      return () -> {};
    }

    @Override
    public void close() throws IOException
    {

    }
  }
}
