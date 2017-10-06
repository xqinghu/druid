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

import io.druid.data.input.Firehose;
import io.druid.data.input.InputRow;
import io.druid.data.input.impl.InputRowParser;
import io.druid.java.util.common.ISE;
import org.apache.hadoop.mapreduce.InputFormat;
import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.RecordReader;
import org.apache.hadoop.mapreduce.TaskAttemptContext;

import javax.annotation.Nullable;
import java.io.IOException;
import java.util.List;

public class HadoopFirehose implements Firehose
{
  private final InputRowParser parser;
  private final InputFormat<?, ?> inputFormat;
  private final List<InputSplit> splits;
  private final TaskAttemptContext taskAttemptContext;

  private int nextSplit = 0;
  private RecordReader<?, ?> currentRecordReader = null;
  private boolean rowValid = false;
  private Object nextValue;

  public HadoopFirehose(
      final InputRowParser parser,
      final InputFormat<?, ?> inputFormat,
      final List<InputSplit> splits,
      final TaskAttemptContext taskAttemptContext
  )
  {
    this.parser = parser;
    this.inputFormat = inputFormat;
    this.splits = splits;
    this.taskAttemptContext = taskAttemptContext;
  }

  @Override
  public boolean hasMore()
  {
    try {
      while (!rowValid) {
        if (nextSplit >= splits.size()) {
          return false;
        }

        if (currentRecordReader == null) {
          final InputSplit split = splits.get(nextSplit);
          currentRecordReader = inputFormat.createRecordReader(split, taskAttemptContext);
          currentRecordReader.initialize(split, taskAttemptContext);
        }

        final boolean didRead = currentRecordReader.nextKeyValue();

        if (didRead) {
          nextValue = currentRecordReader.getCurrentValue();
          rowValid = true;
        } else {
          nextSplit++;
          currentRecordReader.close();
          currentRecordReader = null;
        }
      }

      return rowValid;
    }
    catch (IOException | InterruptedException e) {
      throw new RuntimeException(e);
    }
  }

  @Nullable
  @Override
  public InputRow nextRow()
  {
    if (!hasMore()) {
      throw new ISE("There is no next row!");
    }

    final InputRow inputRow = parser.parse(nextValue);
    rowValid = false;
    return inputRow;
  }

  @Override
  public Runnable commit()
  {
    return () -> {};
  }

  @Override
  public void close() throws IOException
  {
    if (currentRecordReader != null) {
      currentRecordReader.close();
      nextSplit = splits.size();
    }
  }
}
