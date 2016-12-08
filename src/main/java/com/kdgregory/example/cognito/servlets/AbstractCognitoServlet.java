// Copyright (c) Keith D Gregory, all rights reserved
package com.kdgregory.example.cognito.servlets;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletResponse;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClient;
import com.amazonaws.services.cognitoidp.model.AuthenticationResultType;

import com.kdgregory.example.cognito.util.CredentialsCache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.sf.kdgcommons.lang.StringUtil;


/**
 *  Base class for all servlets; provides common functionality.
 */
public abstract class AbstractCognitoServlet
extends HttpServlet
{
    private static final long serialVersionUID = 1L;

    protected Logger logger = LoggerFactory.getLogger(getClass());
    protected AWSCognitoIdentityProviderClient cognitoClient = new AWSCognitoIdentityProviderClient();

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
