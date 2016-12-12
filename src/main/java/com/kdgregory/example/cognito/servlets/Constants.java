// Copyright (c) Keith D Gregory, all rights reserved
package com.kdgregory.example.cognito.servlets;

/**
 *  Holds constants that cross servlets. These are categorized using static nested classes.
 */
public abstract class Constants
{
    /**
     *  Parameter names. Should be self-explanatory.
     */
    public abstract class RequestParameters
    {
        public final static String  EMAIL = "EMAIL";
        public final static String  PASSWORD = "PASSWORD";
        public final static String  TEMPORARY_PASSWORD = "TEMPORARY_PASSWORD";
    }


    /**
     *  Standard response messages. These strings will constitute the entirety of the response body.
     */
    public abstract class ResponseMessages
    {
        /**
         *  User is not logged in -- client should redirect to sign-in page.
         */
        public final static String NOT_LOGGED_IN = "NOT_LOGGED_IN";

        /**
         *  User is logged in (returned after successful sign-in/sign-up, or from an auth check).
         */
        public final static String LOGGED_IN = "LOGGED_IN";

        /**
         *  Request was mising required parameters
         */
        public final static String INVALID_REQUEST = "INVALID_REQUEST";

        /**
         *  The supplied username and/or password were incorrect.
         *  We do not differentiate between the two cases as a security measure.
         */
        public final static String NO_SUCH_USER = "NO_SUCH_USER";

        /**
         *  Returned by signup when a user with the given email already exists.
         */
        public final static String USER_ALREADY_EXISTS = "USER_ALREADY_EXISTS";

        /**
         *  User was created, must log in and change password.
         */
        public final static String USER_CREATED = "USER_CREATED";
        
        /**
         *  New user attempted to login via normal signin page, needs to go to signup-confirm page.
         */
        public final static String FORCE_PASSWORD_CHANGE = "FORCE_PASSWORD_CHANGE";
        
        /**
         *  Returned when user submits a permanent password that doesn't meet criteria.
         */
        public final static String INVALID_PASSWORD = "INVALID_PASSWORD";
    }


    /**
     *  Names of the cookies used to store credentials.
     */
    public abstract class CookieNames
    {
        public final static String  ACCESS_TOKEN = "ACCESS_TOKEN";
        public final static String  REFRESH_TOKEN = "REFRESH_TOKEN";
    }
}
