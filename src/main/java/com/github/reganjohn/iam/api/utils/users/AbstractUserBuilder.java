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

import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.entities.User;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.UUID;

@SuppressWarnings("unchecked")
public abstract class AbstractUserBuilder<T, R extends AbstractUserBuilder<T, R>> implements UserRequest<R>
{
    protected UUID userId;
    protected String name;
    protected String avatarId;
    protected long flags;

    protected AbstractUserBuilder() {}

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
    public R setName(@Nonnull String name)
    {
        Checks.notEmpty(name, "Name");
        Checks.notLonger(name, User.MAX_NAME_LENGTH, "Name");
        this.name = name;
        return (R) this;
    }

    @Nonnull
    @Override
    public String getName()
    {
        return name;
    }

    @Nonnull
    @Override
    public R setAvatarId(@Nullable String avatarId)
    {
        if (avatarId != null)
            Checks.notLonger(avatarId, User.AVATAR_CID_MAX_LENGTH, "Avatar ID");
        this.avatarId = avatarId;
        return (R) this;
    }

    @Nullable
    @Override
    public String getAvatarId()
    {
        return avatarId;
    }

    @Nonnull
    @Override
    public R setUserFlags(long flags)
    {
        this.flags = flags;
        return (R) this;
    }

    @Override
    public long getRawUserFlags()
    {
        return flags;
    }

    public abstract boolean isEmpty();

    public abstract boolean isValid();

    @Nonnull
    public abstract T build();

    @Nonnull
    public R clear()
    {
        this.userId = null;
        this.name = null;
        this.avatarId = null;
        this.flags = 0;
        return (R) this;
    }
}
