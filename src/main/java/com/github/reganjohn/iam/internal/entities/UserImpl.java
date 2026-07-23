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

import com.github.adamorgan.jnt.internal.utils.EntityString;
import com.github.reganjohn.iam.api.IAM;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.internal.IAMImpl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.UUID;

public class UserImpl implements User
{
    private final IAMImpl api;
    private final UUID uniqueId;
    private final String name;
    private final String avatarId;
    private final int flags;

    public UserImpl(@Nonnull IAMImpl api, @Nonnull UUID id, @Nonnull String name, @Nullable String avatarId, int flags)
    {
        this.api = api;
        this.uniqueId = id;
        this.name = name;
        this.avatarId = avatarId;
        this.flags = flags;
    }

    @Nonnull
    @Override
    public UUID getUniqueId()
    {
        return uniqueId;
    }

    @Nonnull
    @Override
    public String getName()
    {
        return name;
    }

    @Nonnull
    @Override
    public IAM getIAM()
    {
        return api;
    }

    @Nullable
    @Override
    public String getAvatarId()
    {
        return avatarId;
    }

    @Override
    public int getFlagsRaw()
    {
        return flags;
    }

    @Override
    public String toString()
    {
        return new EntityString(this)
                .setName(name)
                .toString();
    }
}
