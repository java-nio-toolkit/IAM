/*
 * Copyright 2026 Ada Morgan, John Regan and the JNT contributors
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

import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.EntityString;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.utils.users.UserEditData;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.jact.api.requests.objaction.InteractionMappingAction;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.internal.interactions.InteractionImpl;
import com.reganjohn.jact.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionMappingActionImpl;
import com.reganjohn.jact.internal.utils.InteractionUtil;

import javax.annotation.Nonnull;
import java.util.EnumSet;
import java.util.UUID;

public class UserImpl implements User
{
    private final IAMImpl api;
    private final UUID uniqueId;
    private final String name;
    private final int flags;

    public UserImpl(@Nonnull IAMImpl api, @Nonnull UUID id, @Nonnull String name, int flags)
    {
        this.api = api;
        this.uniqueId = id;
        this.name = name;
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

    @Override
    public int getFlagsRaw()
    {
        return flags;
    }

    @Nonnull
    @Override
    public InteractionMappingAction<Void> edit(@Nonnull UserEditData user)
    {
        Checks.notNull(user, "User");
        String content = Helpers.format("UPDATE users.accounts SET %s WHERE user_id = :user_id IF EXISTS",
                InteractionUtil.join(user.toData().keys(), true));
        return new InteractionMappingActionImpl<>(api.getJACT(), content, Helpers.unnullableMap(user.toMap()))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (InteractionUtil.isDone(array))
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_USER));
            }
        };
    }

    @Override
    public String toString()
    {
        return new EntityString(this)
                .setName(name)
                .toString();
    }
}
