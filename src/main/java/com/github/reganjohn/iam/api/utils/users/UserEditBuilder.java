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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.UUID;

public class UserEditBuilder extends AbstractUserBuilder<UserEditData, UserEditBuilder>
        implements UserEditRequest<UserEditBuilder>
{
    protected static final int USER_ID = 1;
    protected static final int NAME = 1 << 1;
    protected static final int AVATAR_ID = 1 << 2;
    protected static final int FLAGS = 1 << 3;

    private boolean replace = false;
    private int configuredFields = 0;

    public UserEditBuilder() {}

    @Nonnull
    @Override
    public UserEditBuilder setUserId(@Nonnull UUID userId)
    {
        super.setUserId(userId);
        configuredFields |= USER_ID;
        return this;
    }

    @Nonnull
    @Override
    public UserEditBuilder setName(@Nonnull String name)
    {
        super.setName(name);
        configuredFields |= NAME;
        return this;
    }

    @Nonnull
    @Override
    public UserEditBuilder setAvatarId(@Nullable String avatarId)
    {
        super.setAvatarId(avatarId);
        configuredFields |= AVATAR_ID;
        return this;
    }

    @Nonnull
    @Override
    public UserEditBuilder setUserFlags(long flags)
    {
        super.setUserFlags(flags);
        configuredFields |= FLAGS;
        return this;
    }

    @Nonnull
    @Override
    public UserEditBuilder setReplace(boolean isReplace)
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
    public UserEditBuilder applyData(@Nonnull UserEditData data)
    {
        Checks.notNull(data, "UserEditData");
        this.configuredFields |= data.getConfiguredFields();
        this.replace |= data.isReplace();

        if (data.isSet(USER_ID))
            setUserId(data.getUserId());
        if (data.isSet(NAME))
            setName(data.getName());
        if (data.isSet(AVATAR_ID))
            setAvatarId(data.getAvatarId());
        if (data.isSet(FLAGS))
            setUserFlags(data.getRawUserFlags());

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
    public UserEditData build()
    {
        return new UserEditData(configuredFields, replace, userId, name, avatarId, flags);
    }

    @Nonnull
    @Override
    public UserEditBuilder clear()
    {
        this.configuredFields = 0;
        this.replace = false;
        return super.clear();
    }
}
