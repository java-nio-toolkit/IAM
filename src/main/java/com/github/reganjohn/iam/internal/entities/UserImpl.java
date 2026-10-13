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

import com.github.adamorgan.jnt.api.utils.AccessUtil;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryArray;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.EntityString;
import com.github.reganjohn.iam.api.IAM;
import com.github.reganjohn.iam.api.entities.*;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionContextActionImpl;
import com.reganjohn.c4j.internal.utils.InteractionUtil;

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
    public InteractionCallbackAction<AccessEntryArray> retrieveAccess()
    {
        return new InteractionContextActionImpl<>(api.getJCA(), "SELECT * FROM users.public_keys WHERE user_id = ?", Collections.singletonList(userId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
                                      @Nonnull InteractionImpl<AccessEntryArray> interaction,
                                      @Nonnull BufferArray array) throws Exception
            {
                if (array.isEmpty())
                    interaction.onSuccess(AccessUtil.EMPTY_SET);
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
        return new InteractionContextActionImpl<>(api.getJCA(), "SELECT * FROM users.public_keys WHERE user_id = ? AND thumbprint = ?", Arrays.asList(userId, thumbprint))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
                                      @Nonnull InteractionImpl<AccessEntryData> interaction,
                                      @Nonnull BufferArray array) throws Exception
            {
                if (!array.isEmpty() && !EntityBuilder.isDelete(array))
                    interaction.onSuccess(EntityBuilder.createAccessEntry(array.getObject(0)));
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_ACCESS));
            }
        };
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Session> retrieveSessionById(@Nonnull UUID sessionId)
    {
        return api.retrieveSessionById(userId, sessionId);
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<List<Session>> retrieveSessions()
    {
        return api.retrieveSessions(userId);
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Integer> retrieveSessionCount()
    {
        return api.retrieveSessionCount(userId);
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Webhook> retrieveWebhookById(@Nonnull UUID webhookId)
    {
        return api.retrieveWebhookById(userId, webhookId);
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<List<Webhook>> retrieveWebhooks()
    {
        return api.retrieveWebhooks(userId);
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Integer> retrieveWebhookCount()
    {
        return api.retrieveWebhookCount(userId);
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Application> retrieveApplicationById(@Nonnull UUID applicationId)
    {
        return api.retrieveApplicationById(userId, applicationId);
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<List<Application>> retrieveApplications()
    {
        return api.retrieveApplications(userId);
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Integer> retrieveApplicationCount()
    {
        return api.retrieveApplicationCount(userId);
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<PermissionOverride> retrieveEntitlementById(@Nonnull UUID applicationId)
    {
        return api.retrieveEntitlementById(userId, applicationId);
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<List<PermissionOverride>> retrieveEntitlements()
    {
        return api.retrieveEntitlements(userId);
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
        return new InteractionContextActionImpl<>(api.getJCA(), "UPDATE users.accounts SET flags = ? WHERE user_id = ? IF EXISTS", Arrays.asList(flags, userId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
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
