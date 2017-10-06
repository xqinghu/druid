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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import io.druid.data.input.Firehose;
import io.druid.data.input.InputRow;
import io.druid.data.input.impl.DelimitedParseSpec;
import io.druid.data.input.impl.DimensionsSpec;
import io.druid.data.input.impl.TimestampSpec;
import io.druid.indexer.HadoopyStringInputRowParser;
import org.apache.hadoop.mapreduce.lib.input.TextInputFormat;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class HadoopFirehoseFactoryTest
{
  @Rule
  public TemporaryFolder temporaryFolder = new TemporaryFolder();

  @Test
  public void testFileInputFormat() throws Exception
  {
    final File tmp = temporaryFolder.newFolder();

    Files.write(
        new File(tmp.getPath(), "1").toPath(),
        ImmutableList.of(
            "2000\ta",
            "2000\tb"
        ),
        StandardCharsets.UTF_8
    );

    Files.write(
        new File(tmp.getPath(), "2").toPath(),
        ImmutableList.of(),
        StandardCharsets.UTF_8
    );

    Files.write(
        new File(tmp.getPath(), "3").toPath(),
        ImmutableList.of(
            "2000\tc"
        ),
        StandardCharsets.UTF_8
    );

    final HadoopFirehoseFactory firehoseFactory = new HadoopFirehoseFactory(
        TextInputFormat.class.getName(),
        ImmutableMap.of(
            "mapreduce.input.fileinputformat.inputdir", tmp.getPath(),
            "mapreduce.input.fileinputformat.input.dir.recursive", "true"
        )
    );

    final HadoopyStringInputRowParser parser = new HadoopyStringInputRowParser(
        new DelimitedParseSpec(
            new TimestampSpec("one", "auto", null),
            new DimensionsSpec(DimensionsSpec.getDefaultSchemas(ImmutableList.of("two")), null, null),
            "\t",
            null,
            ImmutableList.of("one", "two"),
            false,
            0
        )
    );

    final List<InputRow> rows = new ArrayList<>();

    try (final Firehose firehose = firehoseFactory.connect(parser, temporaryFolder.newFolder())) {
      while (firehose.hasMore()) {
        rows.add(firehose.nextRow());
      }
    }

    Assert.assertEquals(
        ImmutableList.of("a", "b", "c"),
        rows.stream().map(r -> r.getRaw("two")).collect(Collectors.toList())
    );
  }
}
