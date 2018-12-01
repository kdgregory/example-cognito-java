// Copyright (c) Keith D Gregory
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.kdgregory.example.cognito.servlets;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.AuthenticationResultType;

import com.kdgregory.example.cognito.util.CredentialsCache;

import net.sf.kdgcommons.lang.StringUtil;


/**
 *  Base class for all servlets; provides common functionality.
 */
public abstract class AbstractCognitoServlet
extends HttpServlet
{
    private static final long serialVersionUID = 1L;

    protected Logger logger = LoggerFactory.getLogger(getClass());
    protected AWSCognitoIdentityProvider cognitoClient = AWSCognitoIdentityProviderClientBuilder.defaultClient();

    // credentials cache is static so that all validating servlets can check it
    protected static CredentialsCache tokenCache = new CredentialsCache(10000);


    /**
     *  Returns the Cognito pool ID, defined in the servlet context.
     */
    protected String cognitoPoolId()
    {
        return getServletContext().getInitParameter("cognito_pool_id");
    }


    /**
     *  Returns the Cognito client ID, defined in the servlet context.
     */
    protected String cognitoClientId()
    {
        return getServletContext().getInitParameter("cognito_client_id");
    }


    /**
     *  Updates the access and refresh tokens, stored in cookies in the response.
     *  Note that refresh token is optional -- on a refresh, we just get a new
     *  access token.
     *  <p>
     *  Note: also updates the token cache.
     */
    protected void updateCredentialCookies(HttpServletResponse response, AuthenticationResultType authResult)
    {
        tokenCache.addToken(authResult.getAccessToken());

        Cookie accessTokenCookie = new Cookie(Constants.CookieNames.ACCESS_TOKEN, authResult.getAccessToken());
        response.addCookie(accessTokenCookie);

        if (!StringUtil.isBlank(authResult.getRefreshToken()))
        {
            Cookie refreshTokenCookie = new Cookie(Constants.CookieNames.REFRESH_TOKEN, authResult.getRefreshToken());
            response.addCookie(refreshTokenCookie);
        }
    }


    /**
     *  Writes the response message. All responses use status code 200; the client must
     *  look at the message to determine its action.
     */
    protected void reportResult(HttpServletResponse response, String responseMessage)
    throws ServletException, IOException
    {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/plain");
        try (PrintWriter out = response.getWriter())
        {
            out.print(responseMessage);
        }
    }

}
