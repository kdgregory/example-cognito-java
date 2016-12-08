// Copyright (c) Keith D Gregory, all rights reserved
package com.kdgregory.example.cognito.util;

import org.junit.Test;
import static org.junit.Assert.*;

public class TestCredentialsCache
{
    @Test
    public void testBasicOperation() throws Exception
    {
        CredentialsCache cache = new CredentialsCache(10);
        cache.addToken("foo");

        assertTrue("cached token was found",     cache.checkToken("foo"));
        assertFalse("bogus token was not found", cache.checkToken("bar"));
    }


    @Test
    public void testLRU() throws Exception
    {
        CredentialsCache cache = new CredentialsCache(3);
        cache.addToken("foo");
        cache.addToken("bar");
        cache.addToken("baz");
        cache.addToken("biff");

        assertFalse("earliest token no loger in cache", cache.checkToken("foo"));
        assertTrue("later token (bar) is in cache",     cache.checkToken("bar"));
        assertTrue("later token (baz) is in cache",     cache.checkToken("baz"));
        assertTrue("later token (biff) is in cache",    cache.checkToken("biff"));
    }


    @Test
    public void testTimeout() throws Exception
    {
        CredentialsCache cache = new CredentialsCache(3);
        cache.addToken("foo", -1);

        assertFalse("token no loger in cache", cache.checkToken("foo"));
    }
}
