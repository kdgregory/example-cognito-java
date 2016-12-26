// Copyright (c) Keith D Gregory, all rights reserved
package com.kdgregory.example.cognito.servlets;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import com.amazonaws.services.cognitoidp.model.*;
import net.sf.kdgcommons.lang.StringUtil;
import net.sf.kdgcommons.lang.ThreadUtil;


/**
 *  This servlet initiates the signup process for a new user.
 */
public class SignUp extends AbstractCognitoServlet
{
    private static final long serialVersionUID = 1L;


    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException
    {
        String emailAddress = request.getParameter(Constants.RequestParameters.EMAIL);
        if (StringUtil.isBlank(emailAddress))
        {
            reportResult(response, Constants.ResponseMessages.INVALID_REQUEST);
            return;
        }

        logger.debug("creating user {}", emailAddress);

        try
        {
            AdminCreateUserRequest cognitoRequest = new AdminCreateUserRequest()
                    .withUserPoolId(cognitoPoolId())
                    .withUsername(emailAddress)
                    .withUserAttributes(
                            new AttributeType()
                                .withName("email")
                                .withValue(emailAddress),
                            new AttributeType()
                                .withName("email_verified")
                                .withValue("true"))
                    .withDesiredDeliveryMediums(DeliveryMediumType.EMAIL)
                    .withForceAliasCreation(Boolean.FALSE);

            cognitoClient.adminCreateUser(cognitoRequest);
            reportResult(response, Constants.ResponseMessages.USER_CREATED);
        }
        catch (UsernameExistsException ex)
        {
            logger.debug("user already exists: {}", emailAddress);
            reportResult(response, Constants.ResponseMessages.USER_ALREADY_EXISTS);
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
        return "Handles user signup";
    }

}
