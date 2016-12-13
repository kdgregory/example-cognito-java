// Copyright (c) Keith D Gregory, all rights reserved
package com.kdgregory.example.cognito.util;

import java.io.Serializable;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

/**
 *  Holds access tokens with an associated validity timestamp. The intention is to
 *  minimize the number of calls to Cognito. Tokens should be added to the cache
 *  on successful authentication or refresh. They will time out after 15 minutes,
 *  at which point the servlet must authenticate again.
 *  <p>
 *  To further minimize calls, a single cache should be injected into all servlets.
 *  <p>
 *  Implementation notes:
 *  <ul>
 *  <li> This is an LRU cache based on <code>LinkedHashMap</code>. It's constructed
 *       with the maximum number of retained entries, which should be large enough
 *       to support expected use but small enough to avoid straining memory.
 *  <li> There is currently no option to purge entries from the cache. This means
 *       that there's no way to force-logout a user once they have been validated.
 *       With the default 15 minute timeout, this shouldn't be an issue in practice.
 *  <li> The cache is naively syncrhonized. In normal use this should be sufficient
 *       and cause minimal contention. In high-volume use, consider replacing with
 *       a <code>ConcurrentHashMap</code> and reaper thread.
 *  <li> The cache is marked Serializable so that it can be used with servlets. In
 *       a production app, the actual map would be marked transient (and in practice
 *       it would never be serialized, as the servlet would never be passivated). See
 *       http://blog.kdgregory.com/2015/11/java-object-serialization-and-untrusted.html
 *       for the problems with naively serializing maps.
 *  </ul>
 */
public class CredentialsCache
implements Serializable
{
    private static final long serialVersionUID = 1L;

    private static final long DEFAULT_TIMEOUT = 15 * 60 * 1000L;

    private Map<String,Date> cache;


    /**
     *  Creates a new cache, holding up to <code>maxEntries</code> entries.
     */
    public CredentialsCache(final int maxEntries)
    {
        cache = Collections.synchronizedMap(new LinkedHashMap<String,Date>()
        {
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Entry<String,Date> eldest)
            {
                return size() > maxEntries;
            }
        });
    }


    /**
     *  Adds an access token to the cache, with default (1 hour) timeout.
     */
    public void addToken(String accessToken)
    {
        addToken(accessToken, DEFAULT_TIMEOUT);
    }


    /**
     *  Adds an access token to the cache with specified timeout (in millis).
     *  This should be called when an uncached token has been validated (which
     *  would happen when the app restarts).
     */
    public void addToken(String accessToken, long timeoutMillis)
    {
        cache.put(accessToken, new Date(System.currentTimeMillis() + timeoutMillis));
    }

    /**
     *  Checks the cache for the given access token, returning true if the token
     *  exists and has not yet timed out.
     */
    public boolean checkToken(String accessToken)
    {
        Date expirationDate = cache.get(accessToken);
        if (expirationDate == null)
        {
            return false;
        }
        else if (System.currentTimeMillis() > expirationDate.getTime())
        {
            cache.remove(accessToken);
            return false;
        }
        else
        {
            return true;
        }
    }
}
