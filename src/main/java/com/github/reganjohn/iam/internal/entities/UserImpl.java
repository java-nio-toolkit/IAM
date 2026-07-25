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
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.entities.PermissionOverride;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.internal.interactions.InteractionImpl;
import com.reganjohn.jact.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionContextActionImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionMappingActionImpl;
import com.reganjohn.jact.internal.utils.InteractionUtil;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collections;
import java.util.List;
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

    @Nonnull
    @Override
    public InteractionCallbackAction<List<Session>> retrieveSessions()
    {
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM users.sessions WHERE user_id = ?", Collections.singletonList(uniqueId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<List<Session>> interaction,
                                      @Nonnull BufferArray array)
            {
                interaction.onSuccess(array.isEmpty() ? Collections.emptyList() : getIAM().getEntityBuilder().createSessions(array));
            }
        };
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Integer> retrieveSessionCount()
    {
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT COUNT(*) FROM users.sessions WHERE user_id = ?", Collections.singletonList(uniqueId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Integer> request, @Nonnull BufferArray array)
            {
                request.onSuccess((int) InteractionUtil.count(array));
            }
        };
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<List<Application>> retrieveApplications()
    {
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM integrations.applications WHERE user_id = ?", Collections.singletonList(uniqueId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<List<Application>> interaction,
                                      @Nonnull BufferArray array)
            {
                interaction.onSuccess(array.isEmpty() ? Collections.emptyList() : getIAM().getEntityBuilder().createApplications(array));
            }
        };
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Integer> retrieveApplicationCount()
    {
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM integrations.applications WHERE user_id = :user_id", Collections.singletonList(uniqueId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Integer> request, @Nonnull BufferArray array)
            {
                request.onSuccess((int) InteractionUtil.count(array));
            }
        };
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<List<PermissionOverride>> retrieveEntitlements()
    {
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM users.entitlement WHERE user_id = ?", Collections.singletonList(uniqueId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<List<PermissionOverride>> interaction,
                                      @Nonnull BufferArray array)
            {
                if (!array.isEmpty())
                    interaction.onSuccess(getIAM().getEntityBuilder().createPermissionOverrides(array));
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_ENTITLEMENT));
            }
        };
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Void> delete()
    {
        return new InteractionMappingActionImpl<>(api.getJACT(), ClassLoader.getResourceAsString("delete_account.cql"), Collections.singletonMap("user_id", uniqueId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (!array.isEmpty())
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_USER));
            }
        };
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
