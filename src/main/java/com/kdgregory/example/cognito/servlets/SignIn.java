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
 *  This servlet handles normal user sign-in, based on username and password.
 */
public class SignIn extends AbstractCognitoServlet
{
    private static final long serialVersionUID = 1L;


    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException
    {
        String emailAddress = request.getParameter(Constants.RequestParameters.EMAIL);
        String password = request.getParameter(Constants.RequestParameters.PASSWORD);
        if (StringUtil.isBlank(emailAddress) || StringUtil.isBlank(password))
        {
            reportResult(response, Constants.ResponseMessages.INVALID_REQUEST);
            return;
        }

        logger.debug("authenticating {}", emailAddress);

        try
        {
            Map<String,String> authParams = new HashMap<String,String>();
            authParams.put("USERNAME", emailAddress);
            authParams.put("PASSWORD", password);

            AdminInitiateAuthRequest cognitoRequest = new AdminInitiateAuthRequest()
                    .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                    .withAuthParameters(authParams)
                    .withClientId(cognitoClientId())
                    .withUserPoolId(cognitoPoolId());

            AdminInitiateAuthResult cognitoResult = cognitoClient.adminInitiateAuth(cognitoRequest);
            if (StringUtil.isBlank(cognitoResult.getChallengeName()))
            {
                updateCredentialCookies(response, cognitoResult.getAuthenticationResult());
                reportResult(response, Constants.ResponseMessages.LOGGED_IN);
                return;
            }

            reportResult(response, cognitoResult.getChallengeName());
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
        return "Handles user signin";
    }

}
