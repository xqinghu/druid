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

package io.druid.security.kerberos;

import com.fasterxml.jackson.annotation.JacksonInject;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.google.common.base.Throwables;
import com.metamx.http.client.HttpClient;
import io.druid.guice.annotations.Self;
import io.druid.java.util.common.logger.Logger;
import io.druid.server.DruidNode;
import io.druid.server.security.AuthConfig;
import io.druid.server.security.Authenticator;
import org.apache.commons.codec.binary.Base64;
import org.apache.hadoop.security.SecurityUtil;
import org.apache.hadoop.security.authentication.client.AuthenticatedURL;
import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.server.AuthenticationFilter;
import org.apache.hadoop.security.authentication.server.AuthenticationHandler;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;
import org.apache.hadoop.security.authentication.util.KerberosUtil;
import org.apache.hadoop.security.authentication.util.Signer;
import org.apache.hadoop.security.authentication.util.SignerException;
import sun.security.krb5.EncryptedData;
import sun.security.krb5.EncryptionKey;
import sun.security.krb5.internal.APReq;
import sun.security.krb5.internal.EncTicketPart;
import sun.security.krb5.internal.Krb5;
import sun.security.krb5.internal.Ticket;
import sun.security.krb5.internal.crypto.KeyUsage;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.security.Principal;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@JsonTypeName("kerberos")
public class KerberosAuthenticator implements Authenticator
{
  private static final Logger log = new Logger(KerberosAuthenticator.class);
  private static final Pattern HADOOP_AUTH_COOKIE_REGEX = Pattern.compile(".*p=(\\S+)&t=.*");

  private final SpnegoFilterConfig spnegoConfig;
  private final AuthenticationKerberosConfig authConfig;
  private final DruidNode node;
  private LoginContext loginContext;

  @JsonCreator
  public KerberosAuthenticator(
      @JacksonInject AuthenticationKerberosConfig authConfig,
      @JacksonInject SpnegoFilterConfig spnegoConfig,
      @Self DruidNode node
  )
  {
    this.spnegoConfig = spnegoConfig;
    this.authConfig = authConfig;
    this.node = node;
  }

  @Override
  public Filter getFilter()
  {
    return new AuthenticationFilter()
    {
      private Signer mySigner;

      @Override
      public void init(FilterConfig filterConfig) throws ServletException
      {
        ClassLoader prevLoader = Thread.currentThread().getContextClassLoader();
        try {
          // AuthenticationHandler is created during Authenticationfilter.init using reflection with thread context class loader.
          // In case of druid since the class is actually loaded as an extension and filter init is done in main thread.
          // We need to set the classloader explicitly to extension class loader.
          Thread.currentThread().setContextClassLoader(AuthenticationFilter.class.getClassLoader());
          super.init(filterConfig);
          String configPrefix = filterConfig.getInitParameter(CONFIG_PREFIX);
          configPrefix = (configPrefix != null) ? configPrefix + "." : "";
          Properties config = getConfiguration(configPrefix, filterConfig);
          String signatureSecret = config.getProperty(configPrefix + SIGNATURE_SECRET);
          if (signatureSecret == null) {
            signatureSecret = Long.toString(new Random().nextLong());
            log.warn("'signature.secret' configuration not set, using a random value as secret");
          }
          //mySigner = new Signer(signatureSecret.getBytes());
        }
        finally {
          Thread.currentThread().setContextClassLoader(prevLoader);
        }
      }

      @Override
      protected AuthenticationToken getToken(HttpServletRequest request) throws IOException, AuthenticationException {
        AuthenticationToken token = null;
        String tokenStr = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
          for (Cookie cookie : cookies) {
            if (cookie.getName().equals(AuthenticatedURL.AUTH_COOKIE)) {
              tokenStr = cookie.getValue();
              try {
                tokenStr = mySigner.verifyAndExtract(tokenStr);
              } catch (SignerException ex) {
                throw new AuthenticationException(ex);
              }
              break;
            }
          }
        }
        if (tokenStr != null) {
          token = AuthenticationToken.parse(tokenStr);
          if (!token.getType().equals(getAuthenticationHandler().getType())) {
            throw new AuthenticationException("Invalid AuthenticationToken type");
          }
          if (token.isExpired()) {
            throw new AuthenticationException("AuthenticationToken expired");
          }
        }
        return token;
      }

      @Override
      public void doFilter(
          ServletRequest request, ServletResponse response, FilterChain filterChain
      ) throws IOException, ServletException
      {
        HttpServletRequest httpReq = (HttpServletRequest) request;

        // If there's already an auth token, then we have authenticated already, skip this.
        if (request.getAttribute(AuthConfig.DRUID_AUTH_TOKEN) != null) {
          filterChain.doFilter(request, response);
          return;
        }

        if (loginContext == null) {
          initializeKerberosLogin();
        }

        String path = ((HttpServletRequest) request).getRequestURI();
        if (isExcluded(path)) {
          filterChain.doFilter(request, response);
        } else {
          String clientPrincipal;
          try {
            Cookie[] cookies = httpReq.getCookies();
            if (cookies == null) {
              clientPrincipal = getPrincipalFromRequestNew((HttpServletRequest) request);
            } else {
              clientPrincipal = null;
              for (Cookie cookie : cookies) {
                if ("hadoop.auth".equals(cookie.getName())) {
                  Matcher matcher = HADOOP_AUTH_COOKIE_REGEX.matcher(cookie.getValue());
                  if (matcher.matches()) {
                    clientPrincipal = matcher.group(1);
                    break;
                  }
                }
              }
            }
          } catch (Exception ex) {
            clientPrincipal = null;
          }

          request.setAttribute(AuthConfig.DRUID_AUTH_TOKEN, clientPrincipal);
        }

        doFilterSuper(request, response, filterChain);
      }

      private void doFilterSuper(ServletRequest request, ServletResponse response, FilterChain filterChain)
          throws IOException, ServletException {
        boolean unauthorizedResponse = true;
        String unauthorizedMsg = "";
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        AuthenticationHandler authHandler = getAuthenticationHandler();
        try {
          boolean newToken = false;
          AuthenticationToken token;
          try {
            token = getToken(httpRequest);
          }
          catch (AuthenticationException ex) {
            log.warn("AuthenticationToken ignored: " + ex.getMessage());
            token = null;
          }
          if (authHandler.managementOperation(token, httpRequest, httpResponse)) {
            if (token == null) {
              if (log.isDebugEnabled()) {
                log.debug("Request [{}] triggering authentication", getRequestURL(httpRequest));
              }
              token = authHandler.authenticate(httpRequest, httpResponse);
              if (token != null && token.getExpires() != 0 &&
                  token != AuthenticationToken.ANONYMOUS) {
                token.setExpires(System.currentTimeMillis() + getValidity() * 1000);
              }
              newToken = true;
            }
            if (token != null) {
              unauthorizedResponse = false;
              if (log.isDebugEnabled()) {
                log.debug("Request [{}] user [{}] authenticated", getRequestURL(httpRequest), token.getUserName());
              }
              final AuthenticationToken authToken = token;
              httpRequest = new HttpServletRequestWrapper(httpRequest) {

                @Override
                public String getAuthType() {
                  return authToken.getType();
                }

                @Override
                public String getRemoteUser() {
                  return authToken.getUserName();
                }

                @Override
                public Principal getUserPrincipal() {
                  return (authToken != AuthenticationToken.ANONYMOUS) ? authToken : null;
                }
              };
              if (newToken && !token.isExpired() && token != AuthenticationToken.ANONYMOUS) {
                String signedToken = mySigner.sign(token.toString());
                //Cookie cookie = createCookie(signedToken);
                //httpResponse.addCookie(cookie);
              }
              filterChain.doFilter(httpRequest, httpResponse);
            }
          } else {
            unauthorizedResponse = false;
          }
        } catch (AuthenticationException ex) {
          unauthorizedMsg = ex.toString();
          log.warn("Authentication exception: " + ex.getMessage(), ex);
        }

        if (unauthorizedResponse) {
          String authorization = ((HttpServletRequest) request).getHeader("Authorization");
          if (authorization == null || !authorization.startsWith(org.apache.hadoop.security.authentication.client.KerberosAuthenticator.NEGOTIATE)) {
            // the request did not try to use Negotiate scheme, move on to the next filter, we'll
            // send out a response challenge header at the end of the filter chain
            filterChain.doFilter(httpRequest, httpResponse);
          } else {
            // the request failed to authenticate with Negotiate scheme, send an error now
            if (!httpResponse.isCommitted()) {
              //Cookie cookie = createCookie("");
              //cookie.setMaxAge(0);
              //httpResponse.addCookie(cookie);
              httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, unauthorizedMsg);
            }
          }
        }
      }
    };
  }

  @Override
  public Class<? extends Filter> getFilterClass()
  {
    return null;
  }

  @Override
  public Map<String, String> getInitParameters()
  {
    Map<String, String> params = new HashMap<String, String>();
    try {
      params.put(
          "kerberos.principal",
          SecurityUtil.getServerPrincipal(spnegoConfig.getPrincipal(), node.getHost())
      );
      params.put("kerberos.keytab", spnegoConfig.getKeytab());
      params.put(AuthenticationFilter.AUTH_TYPE, "kerberos");
      params.put("kerberos.name.rules", spnegoConfig.getAuthToLocal());
      if (spnegoConfig.getCookieSignatureSecret() != null) {
        params.put("signature.secret", spnegoConfig.getCookieSignatureSecret());
      }
    }
    catch (IOException e) {
      Throwables.propagate(e);
    }
    return params;
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

  @Override
  public String getAuthChallengeHeader()
  {
    return "Negotiate";
  }

  @Override
  public boolean authenticateJDBCContext(Map<String, Object> context)
  {
    throw new UnsupportedOperationException("JDBC Kerberos auth not supported yet");
  }

  @Override
  public HttpClient createInternalClient(HttpClient baseClient)
  {
    return new KerberosHttpClient(baseClient, authConfig);
  }

  private boolean isExcluded(String path)
  {
    for (String excluded : spnegoConfig.getExcludedPaths()) {
      if (path.startsWith(excluded)) {
        return true;
      }
    }
    return false;
  }


  /**
   * Kerberos context configuration for the JDK GSS library.
   */
  private static class KerberosConfiguration extends Configuration
  {
    private String keytab;
    private String principal;

    public KerberosConfiguration(String keytab, String principal) {
      this.keytab = keytab;
      this.principal = principal;
    }

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
      Map<String, String> options = new HashMap<String, String>();
      if (System.getProperty("java.vendor").contains("IBM")) {
        options.put("useKeytab",
                    keytab.startsWith("file://") ? keytab : "file://" + keytab);
        options.put("principal", principal);
        options.put("credsType", "acceptor");
      } else {
        options.put("keyTab", keytab);
        options.put("principal", principal);
        options.put("useKeyTab", "true");
        options.put("storeKey", "true");
        options.put("doNotPrompt", "true");
        options.put("useTicketCache", "true");
        options.put("renewTGT", "true");
        options.put("isInitiator", "false");
      }
      options.put("refreshKrb5Config", "true");
      String ticketCache = System.getenv("KRB5CCNAME");
      if (ticketCache != null) {
        if (System.getProperty("java.vendor").contains("IBM")) {
          options.put("useDefaultCcache", "true");
          // The first value searched when "useDefaultCcache" is used.
          System.setProperty("KRB5CCNAME", ticketCache);
          options.put("renewTGT", "true");
          options.put("credsType", "both");
        } else {
          options.put("ticketCache", ticketCache);
        }
      }
      if (log.isDebugEnabled()) {
        options.put("debug", "true");
      }

      return new AppConfigurationEntry[]{
          new AppConfigurationEntry(
              KerberosUtil.getKrb5LoginModuleName(),
              AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
              options),};
    }
  }

  private String getPrincipalFromRequestNew(HttpServletRequest req)
  {
    String authorization = req.getHeader(org.apache.hadoop.security.authentication.client.KerberosAuthenticator.AUTHORIZATION);
    if (authorization == null || !authorization.startsWith(org.apache.hadoop.security.authentication.client.KerberosAuthenticator.NEGOTIATE)) {
      return null;
    } else {
      authorization = authorization.substring(org.apache.hadoop.security.authentication.client.KerberosAuthenticator.NEGOTIATE.length()).trim();
      final Base64 base64 = new Base64(0);
      final byte[] clientToken = base64.decode(authorization);
      try {
        DerInputStream ticketStream = new DerInputStream(clientToken);
        DerValue[] values = ticketStream.getSet(clientToken.length, true);

        // see this link for AP-REQ format: https://tools.ietf.org/html/rfc1510#section-5.5.1
        for (DerValue value : values) {
          if (isValueAPReq(value)) {
            APReq apReq = new APReq(value);
            Ticket ticket = apReq.ticket;
            EncryptedData encData = ticket.encPart;
            int eType = encData.getEType();

            // find the server's key
            EncryptionKey finalKey = null;
            Subject serverSubj = loginContext.getSubject();
            Set<Object> serverCreds = serverSubj.getPrivateCredentials(Object.class);
            for (Object cred : serverCreds) {
              if (cred instanceof KeyTab) {
                KeyTab serverKeyTab = (KeyTab) cred;
                KerberosPrincipal serverPrincipal = new KerberosPrincipal(spnegoConfig.getPrincipal());
                KerberosKey[] serverKeys = serverKeyTab.getKeys(serverPrincipal);
                for (KerberosKey key : serverKeys) {
                  if (key.getKeyType() == eType) {
                    finalKey = new EncryptionKey(key.getKeyType(), key.getEncoded());
                    break;
                  }
                }
              }
            }

            if (finalKey == null) {
              System.out.println("Could not find matching key from server creds.");
              return null;
            }

            // decrypt the ticket with the server's key
            byte[] decryptedBytes = encData.decrypt(finalKey, KeyUsage.KU_TICKET);
            decryptedBytes = encData.reset(decryptedBytes);
            EncTicketPart decrypted = new EncTicketPart(decryptedBytes);
            String clientPrincipal = decrypted.cname.toString();
            return clientPrincipal;
          }
        }
      } catch (Exception ex) {
        System.out.println("EX MSG: " + ex.getMessage());
        return null;
      }
    }

    return null;
  }

  private boolean isValueAPReq(DerValue value) {
    return value.isConstructed((byte) Krb5.KRB_AP_REQ);
  }
  
  private void initializeKerberosLogin() throws ServletException
  {
    String principal;
    String keytab;

    try {
      principal = SecurityUtil.getServerPrincipal(spnegoConfig.getPrincipal(), node.getHost());
      if (principal == null || principal.trim().length() == 0) {
        throw new ServletException("Principal not defined in configuration");
      }
      keytab = spnegoConfig.getKeytab();
      if (keytab == null || keytab.trim().length() == 0) {
        throw new ServletException("Keytab not defined in configuration");
      }
      if (!new File(keytab).exists()) {
        throw new ServletException("Keytab does not exist: " + keytab);
      }

      Set<Principal> principals = new HashSet<Principal>();
      principals.add(new KerberosPrincipal(principal));
      Subject subject = new Subject(false, principals, new HashSet<Object>(), new HashSet<Object>());

      KerberosConfiguration kerberosConfiguration = new KerberosConfiguration(keytab, principal);

      log.info("Login using keytab "+keytab+", for principal "+principal);
      loginContext = new LoginContext("", subject, null, kerberosConfiguration);
      loginContext.login();

      log.info("Initialized, principal %s from keytab %s", principal, keytab);
    } catch (Exception ex) {
      throw new ServletException(ex);
    }
  }
}
