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

package io.druid.security.basic.authentication;

import com.fasterxml.jackson.annotation.JacksonInject;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.metamx.http.client.CredentialedHttpClient;
import com.metamx.http.client.HttpClient;
import com.metamx.http.client.auth.BasicCredentials;
import io.druid.security.basic.db.BasicSecurityStorageConnector;
import io.druid.server.security.AuthConfig;
import io.druid.server.security.AuthenticationUtils;
import io.druid.server.security.Authenticator;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.EnumSet;
import java.util.Map;

@JsonTypeName("basic")
public class BasicHTTPAuthenticator implements Authenticator
{
  private final BasicSecurityStorageConnector dbConnector;
  private final AuthConfig authConfig;

  @JsonCreator
  public BasicHTTPAuthenticator(
    @JacksonInject BasicSecurityStorageConnector dbConnector,
    @JacksonInject AuthConfig authConfig
  )
  {
    this.dbConnector = dbConnector;
    this.authConfig = authConfig;
  }

  @Override
  public Filter getFilter()
  {
    return new BasicHTTPAuthenticationFilter();
  }

  @Override
  public String getAuthChallengeHeader()
  {
    return "Basic";
  }

  @Override
  public boolean authenticateJDBCContext(Map<String, Object> context)
  {
    String user = (String) context.get("user");
    String password = (String) context.get("password");

    if (user == null || password == null) {
      return false;
    }

    return dbConnector.checkCredentials(user, password.toCharArray());
  }

  @Override
  public HttpClient createInternalClient(HttpClient baseClient)
  {
    return new CredentialedHttpClient(
        new BasicCredentials(authConfig.getSystemPrincipal(), authConfig.getSystemPrincipalSecret()),
        baseClient
    );
  }

  @Override
  public Class<? extends Filter> getFilterClass()
  {
    return BasicHTTPAuthenticationFilter.class;
  }

  @Override
  public Map<String, String> getInitParameters()
  {
    return null;
  }

  @Override
  public String getPath()
  {
    return "/*";
  }

  @Override
  public EnumSet<DispatcherType> getDispatcherType()
  {
    return null;
  }

  public class BasicHTTPAuthenticationFilter implements Filter
  {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException
    {

    }

    @Override
    public void doFilter(
        ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain
    ) throws IOException, ServletException
    {
      if (!authConfig.isEnabled()) {
        filterChain.doFilter(servletRequest, servletResponse);
        return;
      }

      HttpServletResponse httpResp = (HttpServletResponse) servletResponse;
      String userSecret = AuthenticationUtils.getBasicUserSecretFromHttpReq((HttpServletRequest) servletRequest);
      if (userSecret == null) {
        // Request didn't have HTTP Basic auth credentials, move on to the next filter
        filterChain.doFilter(servletRequest, servletResponse);
        return;
      }

      String[] splits = userSecret.split(":");
      if (splits.length != 2) {
        httpResp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        return;
      }

      String user = splits[0];
      char[] password = splits[1].toCharArray();

      if (dbConnector.checkCredentials(user, password)) {
        servletRequest.setAttribute(AuthConfig.DRUID_AUTH_TOKEN, user);
        filterChain.doFilter(servletRequest, servletResponse);
      } else {
        httpResp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
      }
    }

    @Override
    public void destroy()
    {

    }
  }
}
