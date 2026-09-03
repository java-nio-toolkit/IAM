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
import com.reganjohn.c4j.api.interactions.context.InteractionMapping;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Map;
import java.util.UUID;

public class SessionCreateData implements SessionData
{
    private final UUID sessionId;
    private final UUID userId;
    private final String userAgent;
    private final AccessEntryData entryData;
    private final long flags;
    private final String thumbprint;

    public SessionCreateData(@Nonnull UUID userId, @Nonnull UUID sessionId, @Nonnull String userAgent,
                             @Nonnull AccessEntryData entryData, long flags, @Nonnull String thumbprint)
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
    public long getRawSessionFlags()
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
    public Map<String, Object> toMap()
    {
        return new InteractionMapping.Builder()
                .put("user_id", userId)
                .put("session_id", sessionId)
                .put("flags", flags)
                .put("user_agent", userAgent)
                .put("alg", entryData.getMode().getName())
                .put("kid", entryData.getUniqueId())
                .put("kty", entryData.getType().name())
                .put("usage", entryData.getUsage().name().toLowerCase())
                .put("access_flags", 0L)
                .put("thumbprint", thumbprint)
                .put("public_key", entryData.getPublic().getEncoded())
                .toMap();
    }

    @Nonnull
    @Override
    public DataObject toData()
    {
        return DataObject.empty()
                .put("user_id", userId)
                .put("session_id", sessionId)
                .put("flags", flags)
                .toData();
    }
}
