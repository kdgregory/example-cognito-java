// Copyright (c) Keith D Gregory, all rights reserved
package com.kdgregory.example.cognito.servlets;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sf.kdgcommons.lang.StringUtil;
import net.sf.kdgcommons.lang.ThreadUtil;

import com.amazonaws.services.cognitoidp.model.AWSCognitoIdentityProviderException;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.GetUserRequest;
import com.amazonaws.services.cognitoidp.model.GetUserResult;
import com.amazonaws.services.cognitoidp.model.NotAuthorizedException;
import com.amazonaws.services.cognitoidp.model.TooManyRequestsException;


/**
 *  This servlet takes the place of some action that requires a valid user. It simply
 *  returns text indicating whether or not the user is authenticated.
 *  <p>
 *  In a real application, this validation logic (and associated cache) should be pushed
 *  into the abstract servlet.
 */
public class ValidatedAction extends AbstractCognitoServlet
{
    private static final long serialVersionUID = 1L;



    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException
    {
        String accessToken = null;
        String refreshToken = null;

        logger.debug("attempting validation");

        Cookie[] cookies = request.getCookies();
        if (cookies == null)
        {
            logger.warn("request from {} did not have cookies", request.getRemoteAddr());
            reportResult(response, Constants.ResponseMessages.NOT_LOGGED_IN);
            return;
        }

        for (Cookie cookie : cookies)
        {
            if (cookie.getName().equals(Constants.CookieNames.ACCESS_TOKEN))
                accessToken = cookie.getValue();
            if (cookie.getName().equals(Constants.CookieNames.REFRESH_TOKEN))
                refreshToken = cookie.getValue();
        }

        if (tokenCache.checkToken(accessToken))
        {
            logger.debug("token was found in cache, not going to AWS");
            reportResult(response, Constants.ResponseMessages.LOGGED_IN);
            return;
        }

        try
        {
            GetUserRequest initialRequest = new GetUserRequest().withAccessToken(accessToken);
            GetUserResult initialResponse = cognitoClient.getUser(initialRequest);

            logger.debug("successful validation for {}", initialResponse.getUsername());
            tokenCache.addToken(accessToken);
            reportResult(response, Constants.ResponseMessages.LOGGED_IN);
        }
        catch (NotAuthorizedException ex)
        {
            if (ex.getErrorMessage().equals("Access Token has expired"))
            {
                attemptRefresh(refreshToken, response);
            }
            else
            {
                logger.warn("exception during validation: {}", ex.getMessage());
                reportResult(response, Constants.ResponseMessages.NOT_LOGGED_IN);
            }
        }
        catch (TooManyRequestsException ex)
        {
            logger.warn("caught TooManyRequestsException, delaying then retrying");
            ThreadUtil.sleepQuietly(250);
            doPost(request, response);
        }
    }


    /**
     *  Attempts to create a new access token based on the provided refresh token.
     */
    private void attemptRefresh(String refreshToken, HttpServletResponse response)
    throws ServletException, IOException
    {
        try
        {
            Map<String,String> authParams = new HashMap<String,String>();
            authParams.put("REFRESH_TOKEN", refreshToken);

            AdminInitiateAuthRequest refreshRequest = new AdminInitiateAuthRequest()
                                              .withAuthFlow(AuthFlowType.REFRESH_TOKEN)
                                              .withAuthParameters(authParams)
                                              .withClientId(cognitoClientId())
                                              .withUserPoolId(cognitoPoolId());

            AdminInitiateAuthResult refreshResponse = cognitoClient.adminInitiateAuth(refreshRequest);
            if (StringUtil.isBlank(refreshResponse.getChallengeName()))
            {
                logger.debug("successfully refreshed token");
                updateCredentialCookies(response, refreshResponse.getAuthenticationResult());
                reportResult(response, Constants.ResponseMessages.LOGGED_IN);
            }
            else
            {
                logger.warn("unexpected challenge when refreshing token: {}", refreshResponse.getChallengeName());
                reportResult(response, Constants.ResponseMessages.NOT_LOGGED_IN);
            }
        }
        catch (AWSCognitoIdentityProviderException ex)
        {
            logger.debug("exception during token refresh: {}", ex.getMessage());
            reportResult(response, Constants.ResponseMessages.NOT_LOGGED_IN);
        }
    }


    @Override
    public String getServletInfo()
    {
        return "Handles user signup";
    }

}
