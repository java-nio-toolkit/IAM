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
import com.reganjohn.jact.api.interactions.context.InteractionMapping;
import org.jetbrains.annotations.Unmodifiable;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Map;
import java.util.UUID;

public class UserEditData implements UserData, InteractionMapping
{
    private final UUID userId;
    private final String username;
    private final String avatarId;
    private final long flags;

    public UserEditData(@Nonnull UUID userId, @Nonnull String name, @Nullable String avatarId, long flags)
    {
        this.userId = userId;
        this.username = name;
        this.avatarId = avatarId;
        this.flags = flags;
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
        return flags;
    }

    @Nonnull
    @Unmodifiable
    public Map<String, Object> toMap()
    {
        return new InteractionMapping.Builder()
                .put("user_id", userId)
                .put("username", username)
                .put("avatar_id", avatarId)
                .put("flags", flags)
                .toMap();
    }

    @Nonnull
    @Override
    public DataObject toData()
    {
        return DataObject.empty()
                .put("user_id", userId)
                .put("username", username)
                .put("avatar_id", avatarId)
                .put("flags", flags)
                .toData();
    }
}
