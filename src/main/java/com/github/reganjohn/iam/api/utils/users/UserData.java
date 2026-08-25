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

import com.github.adamorgan.jnt.api.utils.data.SerializableData;
import com.github.reganjohn.iam.api.entities.User;
import com.reganjohn.c4j.api.interactions.context.InteractionMapping;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.EnumSet;
import java.util.UUID;

public interface UserData extends SerializableData, InteractionMapping
{
    @Nonnull
    UUID getUserId();

    @Nonnull
    String getName();

    @Nullable
    String getAvatarId();

    long getRawUserFlags();

    @Nonnull
    default EnumSet<User.UserFlag> getUserFlags()
    {
        return User.UserFlag.getFlags(getRawUserFlags());
    }
}
