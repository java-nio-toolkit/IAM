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
import com.github.adamorgan.jnt.api.utils.data.SerializableData;
import com.github.reganjohn.iam.api.utils.sessions.SessionCreateData;
import com.reganjohn.c4j.api.interactions.context.InteractionMapping;
import org.jetbrains.annotations.Unmodifiable;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Map;
import java.util.UUID;

public class UserCreateData implements UserData, SerializableData, InteractionMapping
{
    private final UUID userId;
    private final String username;
    private final String avatarId;
    private final long userFlags;
    private final SessionCreateData session;

    protected UserCreateData(@Nonnull UUID userId, @Nonnull String name, @Nullable String avatarId,
                          long userFlags, @Nonnull SessionCreateData session)
    {
        this.userId = userId;
        this.username = name;
        this.avatarId = avatarId;
        this.userFlags = userFlags;
        this.session = session;
    }

    @Nonnull
    @Override
    public UUID getUserId()
    {
        return userId;
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

    @Override
    public long getRawUserFlags()
    {
        return userFlags;
    }

    @Nonnull
    public SessionCreateData getSession()
    {
        return session;
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
                .put("session_id", session.getSessionId())
                .put("user_agent", session.getUserAgent())
                .put("session_flags", session.getRawSessionFlags())
                .put("access_flags", 0L)
                .put("kid", session.getAccessEntry().getUniqueId())
                .put("kty", session.getAccessEntry().getType().name())
                .put("alg", session.getAccessEntry().getMode().getName())
                .put("usage", session.getAccessEntry().getUsageRaw())
                .put("public_key", session.getAccessEntry().getPublic().getEncoded())
                .put("thumbprint", session.getThumbprint())
                .toMap();
    }

    @Nonnull
    @Override
    public DataObject toData()
    {
        DataObject sessionData = DataObject.empty()
                .put("session_id", session.getSessionId())
                .put("flags", session.getRawSessionFlags())
                .put("user_agent", session.getUserAgent())
                .put("kid", session.getAccessEntry().getUniqueId())
                .put("kty", session.getAccessEntry().getType().name())
                .put("alg", session.getAccessEntry().getMode().getName())
                .put("usage", session.getAccessEntry().getUsageRaw())
                .put("public_key", session.getAccessEntry().getPublic().getEncoded())
                .put("thumbprint", session.getThumbprint())
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
