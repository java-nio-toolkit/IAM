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

import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.EntityString;
import com.github.reganjohn.iam.api.IAM;
import com.github.reganjohn.iam.api.entities.*;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.internal.interactions.InteractionImpl;
import com.reganjohn.jact.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionContextActionImpl;
import com.reganjohn.jact.internal.utils.InteractionUtil;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class UserImpl implements User
{
    private final IAMImpl api;
    private final UUID userId;
    private final String name;
    private final String avatarId;
    private final long flags;

    public UserImpl(@Nonnull IAMImpl api, @Nonnull UUID id, @Nonnull String name, @Nullable String avatarId, long flags)
    {
        this.api = api;
        this.userId = id;
        this.name = name;
        this.avatarId = avatarId;
        this.flags = flags;
    }

    @Nonnull
    @Override
    public UUID getUniqueId()
    {
        return userId;
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
    public InteractionCallbackAction<List<AccessEntryData>> retrieveAccess()
    {
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM users.public_keys WHERE user_id = ?", Collections.singletonList(userId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<List<AccessEntryData>> interaction,
                                      @Nonnull BufferArray array) throws Exception
            {
                if (array.isEmpty())
                    interaction.onSuccess(Collections.emptyList());
                else
                    interaction.onSuccess(getIAM().getEntityBuilder().createAccessEntries(array));
            }
        };
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<AccessEntryData> retrieveAccessById(@Nonnull String thumbprint)
    {
        Checks.notEmpty(thumbprint, "Thumbprint");
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM users.public_keys WHERE user_id = ? AND thumbprint = ?", Arrays.asList(userId, thumbprint))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<AccessEntryData> interaction,
                                      @Nonnull BufferArray array) throws Exception
            {
                if (!array.isEmpty())
                    interaction.onSuccess(getIAM().getEntityBuilder().createAccessEntry(array.getObject(0)));
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_ACCESS));
            }
        };
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Session> retrieveSessionById(@Nonnull UUID sessionId)
    {
        Checks.notNull(sessionId, "Session ID");
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM users.sessions WHERE user_id = ? AND session_id = ?", Arrays.asList(userId, sessionId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Session> interaction,
                                      @Nonnull BufferArray array)
            {
                if (!array.isEmpty() && !EntityBuilder.isDelete(array))
                    interaction.onSuccess(getIAM().getEntityBuilder().createSession(array.getObject(0)));
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_SESSION));
            }
        };
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<List<Session>> retrieveSessions()
    {
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM users.sessions WHERE user_id = ?", Collections.singletonList(userId))
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
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT COUNT(*) FROM users.sessions WHERE user_id = ?", Collections.singletonList(userId))
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
    public InteractionCallbackAction<Application> retrieveApplicationById(@Nonnull UUID applicationId)
    {
        Checks.notNull(applicationId, "Application ID");
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM integrations.applications WHERE user_id = ? AND application_id = ?", Arrays.asList(userId, applicationId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Application> interaction,
                                      @Nonnull BufferArray array)
            {
                if (!array.isEmpty() && !EntityBuilder.isDelete(array))
                    interaction.onSuccess(getIAM().getEntityBuilder().createApplication(array.getObject(0)));
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_APPLICATION));
            }
        };
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<List<Application>> retrieveApplications()
    {
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM integrations.applications WHERE user_id = ?", Collections.singletonList(userId))
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
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM integrations.applications WHERE user_id = :user_id", Collections.singletonList(userId))
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
    public InteractionCallbackAction<PermissionOverride> retrieveEntitlementById(@Nonnull UUID applicationId)
    {
        Checks.notNull(applicationId, "Application ID");
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM users.entitlements WHERE user_id = ? AND application_id = ?", Arrays.asList(userId, applicationId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<PermissionOverride> interaction,
                                      @Nonnull BufferArray array)
            {
                if (!array.isEmpty() && !EntityBuilder.isDelete(array))
                    interaction.onSuccess(getIAM().getEntityBuilder().createPermissionOverride(array.getObject(0)));
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_ENTITLEMENT));
            }
        };
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<List<PermissionOverride>> retrieveEntitlements()
    {
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM users.entitlements WHERE user_id = ?", Collections.singletonList(userId))
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

    @Override
    public long getFlagsRaw()
    {
        return flags;
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Void> delete()
    {
        long flags = getFlagsRaw() | UserFlag.DELETED.getRawValue();
        return new InteractionContextActionImpl<>(api.getJACT(), "UPDATE users.accounts SET flags = ? WHERE user_id = ? IF EXISTS", Arrays.asList(flags, userId))
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
