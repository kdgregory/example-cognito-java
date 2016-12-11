// Copyright (c) Keith D Gregory, all rights reserved
package com.kdgregory.example.cognito.servlets;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.amazonaws.services.cognitoidp.model.*;
import net.sf.kdgcommons.lang.StringUtil;
import net.sf.kdgcommons.lang.ThreadUtil;


/**
 *  This servlet finishes the signup process for a new user, changing the temporary
 *  password to a final password.
 */
public class ConfirmSignUp extends AbstractCognitoServlet
{
    private static final long serialVersionUID = 1L;


    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException
    {
        String emailAddress = request.getParameter(Constants.RequestParameters.EMAIL);
        String tempPassword = request.getParameter(Constants.RequestParameters.TEMPORARY_PASSWORD);
        String finalPassword = request.getParameter(Constants.RequestParameters.PASSWORD);
        if (StringUtil.isBlank(emailAddress) || StringUtil.isBlank(tempPassword) || StringUtil.isBlank(finalPassword))
        {
            reportResult(response, Constants.ResponseMessages.INVALID_REQUEST);
            return;
        }

        logger.debug("confirming signup of user {}", emailAddress);

        try
        {
            // must attempt signin with temporary password in order to establish session for password change
            // (even though it's documented as not required)

            Map<String,String> initialParams = new HashMap<String,String>();
            initialParams.put("USERNAME", emailAddress);
            initialParams.put("PASSWORD", tempPassword);

            AdminInitiateAuthRequest initialRequest = new AdminInitiateAuthRequest()
                    .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                    .withAuthParameters(initialParams)
                    .withClientId(cognitoClientId())
                    .withUserPoolId(cognitoPoolId());

            AdminInitiateAuthResult initialResponse = cognitoClient.adminInitiateAuth(initialRequest);
            if (ChallengeNameType.fromValue(initialResponse.getChallengeName()) != ChallengeNameType.NEW_PASSWORD_REQUIRED)
            {
                throw new RuntimeException("unexpected challenge: " + initialResponse.getChallengeName());
            }

            Map<String,String> challengeResponses = new HashMap<String,String>();
            challengeResponses.put("USERNAME", emailAddress);
            challengeResponses.put("PASSWORD", tempPassword);
            challengeResponses.put("NEW_PASSWORD", finalPassword);

            AdminRespondToAuthChallengeRequest finalRequest = new AdminRespondToAuthChallengeRequest()
                    .withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
                    .withChallengeResponses(challengeResponses)
                    .withClientId(cognitoClientId())
                    .withUserPoolId(cognitoPoolId())
                    .withSession(initialResponse.getSession());

            AdminRespondToAuthChallengeResult finalResponse = cognitoClient.adminRespondToAuthChallenge(finalRequest);
            if (StringUtil.isBlank(finalResponse.getChallengeName()))
            {
                updateCredentialCookies(response, finalResponse.getAuthenticationResult());
                reportResult(response, Constants.ResponseMessages.LOGGED_IN);
            }
            else
            {
                throw new RuntimeException("unexpected challenge: " + finalResponse.getChallengeName());
            }
        }
        catch (UserNotFoundException ex)
        {
            logger.debug("not found: {}", emailAddress);
            reportResult(response, Constants.ResponseMessages.NO_SUCH_USER);
        }
        catch (NotAuthorizedException ex)
        {
            logger.debug("invalid credentials: {}", emailAddress);
            reportResult(response, Constants.ResponseMessages.NO_SUCH_USER);
        }
        catch (TooManyRequestsException ex)
        {
            logger.warn("caught TooManyRequestsException, delaying then retrying");
            ThreadUtil.sleepQuietly(250);
            doPost(request, response);
        }
    }


    @Override
    public String getServletInfo()
    {
        return "Handles second stage of user signup, replacing temporary password by final";
    }

}
