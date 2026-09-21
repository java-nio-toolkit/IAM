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

@SuppressWarnings("unchecked")
public abstract class AbstractSessionBuilder<T, R extends AbstractSessionBuilder<T, R>> implements SessionRequest<R>
{
    protected UUID userId;
    protected UUID sessionId;
    protected String userAgent;
    protected AccessEntryData accessEntry;
    protected long flags;
    protected String thumbprint;

    protected AbstractSessionBuilder() {}

    @Nonnull
    @Override
    public R setUserId(@Nonnull UUID userId)
    {
        Checks.notNull(userId, "User ID");
        this.userId = userId;
        return (R) this;
    }

    @Nonnull
    @Override
    public UUID getUserId()
    {
        return userId;
    }

    @Nonnull
    @Override
    public R setSessionId(@Nonnull UUID sessionId)
    {
        Checks.notNull(sessionId, "Session ID");
        this.sessionId = sessionId;
        return (R) this;
    }

    @Nonnull
    @Override
    public UUID getSessionId()
    {
        return sessionId;
    }

    @Nonnull
    @Override
    public R setUserAgent(@Nullable String userAgent)
    {
        this.userAgent = userAgent;
        return (R) this;
    }

    @Nullable
    @Override
    public String getUserAgent()
    {
        return userAgent;
    }

    @Nonnull
    @Override
    public R setAccessEntry(@Nonnull AccessEntryData accessEntry)
    {
        Checks.notNull(accessEntry, "Access Entry");
        this.accessEntry = accessEntry;
        return (R) this;
    }

    @Nonnull
    @Override
    public AccessEntryData getAccessEntry()
    {
        return accessEntry;
    }

    @Nonnull
    @Override
    public R setSessionFlags(long flags)
    {
        this.flags = flags;
        return (R) this;
    }

    @Override
    public long getRawSessionFlags()
    {
        return flags;
    }

    @Nonnull
    @Override
    public R setThumbprint(@Nonnull String thumbprint)
    {
        Checks.notEmpty(thumbprint, "Thumbprint");
        this.thumbprint = thumbprint;
        return (R) this;
    }

    @Nonnull
    @Override
    public String getThumbprint()
    {
        return thumbprint;
    }

    public abstract boolean isEmpty();

    public abstract boolean isValid();

    @Nonnull
    public abstract T build();

    @Nonnull
    public R clear()
    {
        this.userId = null;
        this.sessionId = null;
        this.userAgent = null;
        this.accessEntry = null;
        this.flags = 0;
        this.thumbprint = null;
        return (R) this;
    }
}
