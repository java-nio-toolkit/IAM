/*
 * Copyright 2026 Ada Morgan, John Regan and the IAM contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.reganjohn.iam.api.utils.sessions;

import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.internal.utils.Checks;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.UUID;

public class SessionEditBuilder extends AbstractSessionBuilder<SessionEditData, SessionEditBuilder>
        implements SessionEditRequest<SessionEditBuilder>
{
    protected static final int USER_ID = 1;
    protected static final int SESSION_ID = 1 << 1;
    protected static final int USER_AGENT = 1 << 2;
    protected static final int ACCESS_ENTRY = 1 << 3;
    protected static final int FLAGS = 1 << 4;
    protected static final int THUMBPRINT = 1 << 5;

    private boolean replace = false;
    private int configuredFields = 0;

    public SessionEditBuilder() {}

    @Nonnull
    @Override
    public SessionEditBuilder setUserId(@Nonnull UUID userId)
    {
        super.setUserId(userId);
        configuredFields |= USER_ID;
        return this;
    }

    @Nonnull
    @Override
    public SessionEditBuilder setSessionId(@Nonnull UUID sessionId)
    {
        super.setSessionId(sessionId);
        configuredFields |= SESSION_ID;
        return this;
    }

    @Nonnull
    @Override
    public SessionEditBuilder setUserAgent(@Nullable String userAgent)
    {
        super.setUserAgent(userAgent);
        configuredFields |= USER_AGENT;
        return this;
    }

    @Nonnull
    @Override
    public SessionEditBuilder setAccessEntry(@Nonnull AccessEntryData accessEntry)
    {
        super.setAccessEntry(accessEntry);
        configuredFields |= ACCESS_ENTRY;
        return this;
    }

    @Nonnull
    @Override
    public SessionEditBuilder setSessionFlags(long flags)
    {
        super.setSessionFlags(flags);
        configuredFields |= FLAGS;
        return this;
    }

    @Nonnull
    @Override
    public SessionEditBuilder setThumbprint(@Nonnull String thumbprint)
    {
        super.setThumbprint(thumbprint);
        configuredFields |= THUMBPRINT;
        return this;
    }

    @Nonnull
    @Override
    public SessionEditBuilder setReplace(boolean isReplace)
    {
        this.replace = isReplace;
        return this;
    }

    @Override
    public boolean isReplace()
    {
        return replace;
    }

    @Nonnull
    @Override
    public SessionEditBuilder applyData(@Nonnull SessionEditData data)
    {
        Checks.notNull(data, "SessionEditData");
        this.configuredFields |= data.getConfiguredFields();
        this.replace |= data.isReplace();

        if (data.isSet(USER_ID))
            setUserId(data.getUserId());
        if (data.isSet(SESSION_ID))
            setSessionId(data.getSessionId());
        if (data.isSet(USER_AGENT))
            setUserAgent(data.getUserAgent());
        if (data.isSet(ACCESS_ENTRY))
            setAccessEntry(data.getAccessEntry());
        if (data.isSet(FLAGS))
            setSessionFlags(data.getRawSessionFlags());
        if (data.isSet(THUMBPRINT))
            setThumbprint(data.getThumbprint());

        return this;
    }

    @Override
    public boolean isEmpty()
    {
        return !replace && configuredFields == 0;
    }

    @Override
    public boolean isValid()
    {
        return true;
    }

    @Nonnull
    @Override
    public SessionEditData build()
    {
        return new SessionEditData(configuredFields, replace, userId, sessionId, userAgent, accessEntry, flags, thumbprint);
    }

    @Nonnull
    @Override
    public SessionEditBuilder clear()
    {
        this.configuredFields = 0;
        this.replace = false;
        return super.clear();
    }
}
