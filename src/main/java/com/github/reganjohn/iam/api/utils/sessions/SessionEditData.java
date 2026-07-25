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

import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.reganjohn.jact.api.interactions.context.InteractionMapping;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.UUID;

public class SessionEditData implements SessionData
{
    private final UUID sessionId;
    private final UUID userId;
    private final String userAgent;
    private final AccessEntryData entryData;
    private final int flags;
    private final String thumbprint;

    public SessionEditData(@Nonnull UUID userId, @Nonnull UUID sessionId, @Nonnull String userAgent,
                             @Nonnull AccessEntryData entryData, int flags, @Nonnull String thumbprint)
    {
        this.sessionId = sessionId;
        this.userId = userId;
        this.userAgent = userAgent;
        this.entryData = entryData;
        this.flags = flags;
        this.thumbprint = thumbprint;
    }

    @Nonnull
    @Override
    public UUID getUserId()
    {
        return userId;
    }

    @Nonnull
    @Override
    public UUID getSessionId()
    {
        return sessionId;
    }

    @Nullable
    @Override
    public String getUserAgent()
    {
        return userAgent;
    }

    @Nonnull
    @Override
    public AccessEntryData getAccessEntry()
    {
        return entryData;
    }

    @Override
    public int getRawSessionFlags()
    {
        return flags;
    }

    @Nonnull
    @Override
    public String getThumbprint()
    {
        return thumbprint;
    }

    @Nonnull
    public InteractionMapping toMap()
    {
        InteractionMapping.Builder map = new InteractionMapping.Builder();
        map.put("user_id", userId);
        map.put("session_id", sessionId);
        if (Helpers.nonEmpty(userAgent))
            map.put("user_agent", userAgent);
        if (flags != 0)
            map.put("flags", flags);
        return map.build();
    }

    @Nonnull
    @Override
    public DataObject toData()
    {
        DataObject data = DataObject.empty();
        if (Helpers.nonEmpty(userAgent))
            data.put("user_agent", userAgent);
        if (flags != 0)
            data.put("flags", flags);
        return data;
    }
}
