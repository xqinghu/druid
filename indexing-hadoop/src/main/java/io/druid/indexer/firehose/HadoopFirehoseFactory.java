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
import com.google.common.base.Joiner;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import io.druid.data.input.Firehose;
import io.druid.data.input.FirehoseFactory;
import io.druid.data.input.impl.InputRowParser;
import io.druid.guice.ExtensionsConfig;
import io.druid.guice.GuiceInjectors;
import io.druid.initialization.Initialization;
import io.druid.java.util.common.ISE;
import io.druid.java.util.common.logger.Logger;
import io.druid.java.util.common.parsers.ParseException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.mapreduce.InputFormat;
import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.JobContext;
import org.apache.hadoop.mapreduce.JobID;
import org.apache.hadoop.mapreduce.TaskAttemptID;
import org.apache.hadoop.mapreduce.TaskID;
import org.apache.hadoop.mapreduce.TaskType;
import org.apache.hadoop.mapreduce.task.JobContextImpl;
import org.apache.hadoop.mapreduce.task.TaskAttemptContextImpl;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class HadoopFirehoseFactory implements FirehoseFactory<InputRowParser>
{
  private static final Logger log = new Logger(HadoopFirehoseFactory.class);
  private static final ExtensionsConfig EXTENSIONS_CONFIG;

  static {
    EXTENSIONS_CONFIG = GuiceInjectors.makeStartupInjector().getInstance(ExtensionsConfig.class);
  }

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

  @JsonProperty
  public String getInputFormatClass()
  {
    return inputFormatClass;
  }

  @JsonProperty
  public Map<String, String> getProperties()
  {
    return properties;
  }

  @Override
  public Firehose connect(
      final InputRowParser parser,
      final File temporaryDirectory
  ) throws IOException, ParseException
  {
    try {
      // TODO(gianm): Hardcoded = rad
      final Class<?> clazz = tryLoadClass(
          inputFormatClass,
          null
      );

      if (clazz == null) {
        throw new ISE("inputFormatClass[%s] could not be loaded from any available classloader");
      }

      if (!InputFormat.class.isAssignableFrom(clazz)) {
        throw new ISE("inputFormatClass[%s] is not a[%s]", inputFormatClass, InputFormat.class.getName());
      }

      final InputFormat<?, ?> inputFormat = (InputFormat<?, ?>) clazz.newInstance();
      final Configuration configuration = new Configuration();
      properties.forEach(configuration::set);
      final JobID jobId = new JobID("local", 0);
      final JobContext jobContext = new JobContextImpl(configuration, jobId);
      final List<InputSplit> splits = inputFormat.getSplits(jobContext);

      log.info("Connected with splits: %s", splits);
      return new HadoopFirehose(
          parser,
          inputFormat,
          splits,
          new TaskAttemptContextImpl(
              configuration,
              new TaskAttemptID(new TaskID(jobId, TaskType.MAP, 0), 0)
          )
      );
    }
    catch (InstantiationException | IllegalAccessException e) {
      throw new ISE(e, "inputFormatClass[%s] could not be constructed", inputFormatClass);
    }
    catch (InterruptedException e) {
      throw new RuntimeException(e);
    }
  }

  @Nullable
  private static Class<?> tryLoadClass(final String className, final ClassLoader classLoader)
  {
    try {
      return Class.forName(
          className,
          true,
          classLoader == null ? Thread.currentThread().getContextClassLoader() : classLoader
      );
    }
    catch (ClassNotFoundException e) {
      return null;
    }
  }

  // Copied from HadoopTask
  private static ClassLoader buildClassLoader(
      final List<String> hadoopDependencyCoordinates,
      final List<String> defaultHadoopCoordinates
  ) throws MalformedURLException
  {
    final List<String> finalHadoopDependencyCoordinates = hadoopDependencyCoordinates != null
                                                          ? hadoopDependencyCoordinates
                                                          : defaultHadoopCoordinates;

    final List<URL> jobURLs = Lists.newArrayList(
        Arrays.asList(((URLClassLoader) HadoopFirehoseFactory.class.getClassLoader()).getURLs())
    );

    final List<URL> extensionURLs = Lists.newArrayList();
    for (final File extension : Initialization.getExtensionFilesToLoad(EXTENSIONS_CONFIG)) {
      final ClassLoader extensionLoader = Initialization.getClassLoaderForExtension(extension);
      extensionURLs.addAll(Arrays.asList(((URLClassLoader) extensionLoader).getURLs()));
    }

    jobURLs.addAll(extensionURLs);

    final List<URL> localClassLoaderURLs = new ArrayList<>(jobURLs);

    // hadoop dependencies come before druid classes because some extensions depend on them
    final File[] hadoopDependencyFilesToLoad = Initialization.getHadoopDependencyFilesToLoad(
        finalHadoopDependencyCoordinates,
        EXTENSIONS_CONFIG
    );

    for (final File hadoopDependency : hadoopDependencyFilesToLoad) {
      final ClassLoader hadoopLoader = Initialization.getClassLoaderForExtension(hadoopDependency);
      localClassLoaderURLs.addAll(Arrays.asList(((URLClassLoader) hadoopLoader).getURLs()));
    }

    final ClassLoader classLoader = new URLClassLoader(
        localClassLoaderURLs.toArray(new URL[localClassLoaderURLs.size()]),
        null
    );

    final String hadoopContainerDruidClasspathJars;
    if (EXTENSIONS_CONFIG.getHadoopContainerDruidClasspath() == null) {
      hadoopContainerDruidClasspathJars = Joiner.on(File.pathSeparator).join(jobURLs);

    } else {
      List<URL> hadoopContainerURLs = Lists.newArrayList(
          Initialization.getURLsForClasspath(EXTENSIONS_CONFIG.getHadoopContainerDruidClasspath())
      );

      if (EXTENSIONS_CONFIG.getAddExtensionsToHadoopContainer()) {
        hadoopContainerURLs.addAll(extensionURLs);
      }

      hadoopContainerDruidClasspathJars = Joiner.on(File.pathSeparator)
                                                .join(hadoopContainerURLs);
    }

    log.info("Hadoop Container Druid Classpath is set to [%s]", hadoopContainerDruidClasspathJars);

    return classLoader;
  }
}
