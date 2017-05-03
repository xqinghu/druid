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

package io.druid.server.security;

import com.google.inject.Injector;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class StaticResourceFilter implements Filter
{
  private final Injector injector;
  private final AuthConfig authConfig;

  public StaticResourceFilter(Injector injector)
  {
    this.injector = injector;
    authConfig = injector.getInstance(AuthConfig.class);
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException
  {

  }

  @Override
  public void doFilter(
      ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain
  ) throws IOException, ServletException
  {
    if (authConfig.isEnabled()) {
      ((HttpServletRequest) servletRequest).setAttribute(AuthConfig.DRUID_AUTH_TOKEN_CHECKED, true);
      /*
      final ResourceAction resourceAction = new ResourceAction(
          new Resource("static-resource", ResourceType.STATE),
          Action.READ
      );

      final Access authResult = AuthorizationUtils.authorizeResourceAction(
          (HttpServletRequest) servletRequest,
          resourceAction
      );

      if (!authResult.isAllowed()) {
        ((HttpServletResponse) servletResponse).sendError(Response.SC_FORBIDDEN, "Authorization failure.");
        return;
      }
      */
    }

    filterChain.doFilter(servletRequest, servletResponse);
  }

  @Override
  public void destroy()
  {

  }
}
