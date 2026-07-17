/*
 * Copyright 2026 Ada Morgan, John Regan and the IAM contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.reganjohn.iam.internal.entities;

import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.internal.utils.EntityString;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Objects;
import java.util.UUID;

public class SessionImpl implements Session
{
    private final IAMImpl api;
    private final UUID sessionId;
    private final UUID userId;
    private final int flags;
    private final String thumbprint;
    private final String userAgent;

    public SessionImpl(@Nonnull IAMImpl api, @Nonnull UUID userId, @Nonnull UUID sessionId, int flags,
                       @Nonnull String thumbprint, @Nullable String userAgent)
    {
        this.api = api;
        this.sessionId = sessionId;
        this.userId = userId;
        this.flags = flags;
        this.thumbprint = thumbprint;
        this.userAgent = userAgent;
    }

    @Nonnull
    public IAMImpl getIAM()
    {
        return api;
    }

    @Nonnull
    @Override
    public UUID getUniqueId()
    {
        return sessionId;
    }

    @Nonnull
    @Override
    public UUID getUserId()
    {
        return userId;
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<AccessEntryData> getAccessEntry()
    {
        return api.retrieveAccessEntryById(userId, thumbprint);
    }

    @Override
    public int getFlagsRaw()
    {
        return flags;
    }

    @Nonnull
    @Override
    public String getThumbprint()
    {
        return thumbprint;
    }

    @Nullable
    @Override
    public String getUserAgent()
    {
        return userAgent;
    }

    @Override
    public String toString()
    {
        return new EntityString(this)
                .addMetadata("sessionId", sessionId)
                .addMetadata("userId", userId)
                .addMetadata("thumbprint", thumbprint)
                .toString();
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(thumbprint, sessionId, userId);
    }

    @Override
    public boolean equals(Object obj)
    {
        if (!(obj instanceof SessionImpl))
            return false;
        if (obj == this)
            return true;
        SessionImpl other = (SessionImpl) obj;
        return Objects.equals(thumbprint, other.thumbprint)
                && Objects.equals(sessionId, other.sessionId)
                && Objects.equals(userId, other.userId)
                && Objects.equals(userAgent, other.userAgent);
    }
}
