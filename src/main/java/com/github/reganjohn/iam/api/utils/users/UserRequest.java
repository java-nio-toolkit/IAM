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

public interface UserRequest<R extends UserRequest<R>> extends UserData
{
    @Nonnull
    R setUserId(@Nonnull UUID userId);

    @Nonnull
    R setName(@Nonnull String name);

    @Nonnull
    R setAvatarId(@Nullable String avatarId);

    @Nonnull
    R setUserFlags(long flags);

    @Nonnull
    default R applyUser(@Nonnull User user)
    {
        Checks.notNull(user, "User");
        return setUserId(user.getUniqueId())
                .setName(user.getName())
                .setAvatarId(user.getAvatarId())
                .setUserFlags(user.getFlagsRaw());
    }
}
