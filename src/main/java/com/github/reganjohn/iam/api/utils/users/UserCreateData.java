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

package com.github.reganjohn.iam.api.utils.users;

import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.reganjohn.iam.api.utils.sessions.SessionData;
import com.reganjohn.c4j.api.interactions.context.InteractionMapping;
import org.jetbrains.annotations.Unmodifiable;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Map;
import java.util.UUID;

public class UserCreateData implements UserData, SessionData
{
    private final UUID userId;
    private final UUID sessionId;
    private final String username;
    private final String avatarId;
    private final String userAgent;
    private final AccessEntryData data;
    private final long userFlags;
    private final long sessionFlags;
    private final String thumbprint;

    public UserCreateData(@Nonnull UUID userId, @Nonnull UUID sessionId, @Nonnull String name,
                          @Nullable String avatarId, @Nullable String agent, @Nonnull AccessEntryData data,
                          long userFlags, long sessionFlags, @Nonnull String thumbprint)
    {
        this.userId = userId;
        this.sessionId = sessionId;
        this.username = name;
        this.avatarId = avatarId;
        this.userAgent = agent;
        this.data = data;
        this.userFlags = userFlags;
        this.sessionFlags = sessionFlags;
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

    @Nonnull
    @Override
    public String getName()
    {
        return username;
    }

    @Nullable
    @Override
    public String getAvatarId()
    {
        return avatarId;
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
        return data;
    }

    @Override
    public long getRawSessionFlags()
    {
        return sessionFlags;
    }

    @Override
    public long getRawUserFlags()
    {
        return userFlags;
    }

    @Nonnull
    @Override
    public String getThumbprint()
    {
        return thumbprint;
    }

    @Nonnull
    @Unmodifiable
    public Map<String, Object> toMap()
    {
        return new InteractionMapping.Builder()
                .put("user_id", userId)
                .put("username", username)
                .put("avatar_id", avatarId)
                .put("user_flags", userFlags)
                .put("session_id", sessionId)
                .put("user_agent", userAgent)
                .put("session_flags", sessionFlags)
                .put("access_flags", 0L)
                .put("kid", data.getUniqueId())
                .put("kty", data.getType().name())
                .put("alg", data.getMode().getName())
                .put("usage", data.getRawUsage())
                .put("public_key", data.getPublic().getEncoded())
                .put("thumbprint", thumbprint)
                .toMap();
    }

    @Nonnull
    @Override
    public DataObject toData()
    {
        DataObject sessionData = DataObject.empty()
                .put("session_id", sessionId)
                .put("flags", sessionFlags)
                .put("user_agent", userAgent)
                .put("kid", data.getUniqueId())
                .put("kty", data.getType().name())
                .put("alg", data.getMode().getName())
                .put("usage", data.getRawUsage())
                .put("public_key", data.getPublic().getEncoded())
                .put("thumbprint", thumbprint)
                .toData();

        return DataObject.empty()
                .put("user_id", userId)
                .put("username", username)
                .put("avatar_id", avatarId)
                .put("flags", userFlags)
                .put("session", sessionData)
                .toData();
    }
}
