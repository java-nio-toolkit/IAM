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
import com.github.reganjohn.iam.api.utils.sessions.SessionCreateData;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface UserCreateRequest<R extends UserCreateRequest<R>> extends UserRequest<R>
{
    @Nonnull
    R setSession(@Nonnull SessionCreateData session);

    @Nullable
    SessionCreateData getSession();

    @Nonnull
    default R applyData(@Nonnull UserCreateData data)
    {
        Checks.notNull(data, "UserCreateData");
        return setUserId(data.getUserId())
                .setName(data.getName())
                .setAvatarId(data.getAvatarId())
                .setUserFlags(data.getRawUserFlags())
                .setSession(data.getSession());
    }
}
