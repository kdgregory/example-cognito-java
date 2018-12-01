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
