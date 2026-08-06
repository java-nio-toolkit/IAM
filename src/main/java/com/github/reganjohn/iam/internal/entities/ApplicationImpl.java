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

package com.github.reganjohn.iam.internal.entities;

import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.interactions.AccessContextInteraction;
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

public class ApplicationImpl implements Application
{
    private final IAMImpl api;
    private final UUID applicationId;
    private final UUID ownerId;
    private final String name;
    private final String description;
    private final String iconId;
    private final long flags;
    private final List<String> redirectUris;

    public ApplicationImpl(@Nonnull IAMImpl api, @Nonnull UUID id, @Nonnull UUID ownerId, @Nonnull String name,
                           @Nullable String description, @Nullable String iconId, long flags,
                           @Nonnull List<String> redirectUris)
    {
        this.api = api;
        this.applicationId = id;
        this.ownerId = ownerId;
        this.name = name;
        this.description = description;
        this.iconId = iconId;
        this.flags = flags;
        this.redirectUris = redirectUris;
    }

    @Nonnull
    @Override
    public IAMImpl getIAM()
    {
        return api;
    }

    @Nonnull
    @Override
    public UUID getUniqueId()
    {
        return applicationId;
    }

    @Nonnull
    @Override
    public UUID getOwnerId()
    {
        return ownerId;
    }

    @Nonnull
    @Override
    public String getName()
    {
        return name;
    }

    @Nullable
    @Override
    public String getDescription()
    {
        return description;
    }

    @Nullable
    @Override
    public String getIconId()
    {
        return iconId;
    }

    @Nonnull
    @Override
    public List<String> getRedirectUris()
    {
        return Collections.unmodifiableList(redirectUris);
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Integer> retrieveAccessCount()
    {
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT COUNT(*) FROM integrations.public_keys WHERE user_id = ? AND application_id = ?", Arrays.asList(getOwnerId(), getUniqueId()))
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
    public InteractionCallbackAction<AccessContextInteraction> retrieveAccessById(@Nonnull UUID accessId)
    {
        Checks.notNull(accessId, "Access ID");
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM integrations.public_keys WHERE user_id = ? AND application_id = ? AND access_id = ?", Arrays.asList(getOwnerId(), getUniqueId(), accessId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<AccessContextInteraction> interaction,
                                      @Nonnull BufferArray array)
            {
                if (!array.isEmpty() && !EntityBuilder.isDelete(array))
                    interaction.onSuccess(getIAM().getEntityBuilder().createApplicationAccess(ApplicationImpl.this, array.getObject(0)));
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_APPLICATION));
            }
        };
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<List<AccessContextInteraction>> retrieveAccess()
    {
        return new InteractionContextActionImpl<>(api.getJACT(), "SELECT * FROM integrations.public_keys WHERE user_id = ? AND application_id = ?", Arrays.asList(getOwnerId(), getUniqueId()))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<List<AccessContextInteraction>> interaction,
                                      @Nonnull BufferArray array)
            {
                if (!array.isEmpty() && !EntityBuilder.isDelete(array))
                    interaction.onSuccess(getIAM().getEntityBuilder().createApplicationAccess(ApplicationImpl.this, array));
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_APPLICATION));
            }
        };
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Void> delete()
    {
        long flags = getFlagsRaw() | Application.ApplicationFlag.DELETED.getRawValue();
        return new InteractionContextActionImpl<>(api.getJACT(), "UPDATE integrations.applications SET flags = ? WHERE user_id = ? AND application_id = ?", Arrays.asList(flags, getOwnerId(), getUniqueId()));
    }

    @Override
    public long getFlagsRaw()
    {
        return flags;
    }
}
