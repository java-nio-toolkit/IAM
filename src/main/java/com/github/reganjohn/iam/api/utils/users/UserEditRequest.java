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

public interface UserEditRequest<R extends UserEditRequest<R>> extends UserRequest<R>
{
    @Nonnull
    R setReplace(boolean isReplace);

    boolean isReplace();

    @Nonnull
    R applyData(@Nonnull UserEditData data);

    @Nonnull
    default R applyCreateData(@Nonnull UserCreateData data)
    {
        Checks.notNull(data, "UserCreateData");
        return setReplace(true)
                .setUserId(data.getUserId())
                .setName(data.getName())
                .setAvatarId(data.getAvatarId())
                .setUserFlags(data.getRawUserFlags());
    }

    @Nonnull
    @Override
    default R applyUser(@Nonnull User user)
    {
        return UserRequest.super.applyUser(user).setReplace(true);
    }
}
