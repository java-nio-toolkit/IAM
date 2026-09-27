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
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.internal.requests.objaction.InteractionContextActionImpl;
import com.reganjohn.c4j.internal.utils.InteractionUtil;

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
    private final String origin;
    private final long flags;
    private final List<String> redirectUris;

    public ApplicationImpl(@Nonnull IAMImpl api, @Nonnull UUID id, @Nonnull UUID ownerId, @Nonnull String name,
                           @Nullable String description, @Nullable String iconId, @Nonnull String origin, long flags,
                           @Nonnull List<String> redirectUris)
    {
        this.api = api;
        this.applicationId = id;
        this.ownerId = ownerId;
        this.name = name;
        this.description = description;
        this.iconId = iconId;
        this.origin = origin;
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
    public String getOrigin()
    {
        return origin;
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<ApplicationContextInteraction> retrieveInteractionById(@Nonnull UUID id)
    {
        Checks.notNull(id, "Interaction ID");
        return new InteractionContextActionImpl<>(api.getJCA(), "SELECT * FROM integrations.interactions WHERE user_id = :user_id AND application_id = :application_id AND interaction_id = :interaction_id", Arrays.asList(ownerId, applicationId, id))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
                                      @Nonnull InteractionImpl<ApplicationContextInteraction> interaction,
                                      @Nonnull BufferArray array)
            {
                if (!array.isEmpty())
                    interaction.onSuccess(getIAM().getEntityBuilder().createContextInteraction(array.getObject(0)));
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_INTERACTION));
            }
        };
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Void> delete()
    {
        long flags = getFlagsRaw() | Application.ApplicationFlag.DELETED.getRawValue();
        return new InteractionContextActionImpl<>(api.getJCA(), "UPDATE integrations.applications SET flags = ? WHERE owner_id = ? AND application_id = ? IF EXISTS", Arrays.asList(flags, getOwnerId(), getUniqueId()))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (InteractionUtil.isDone(array))
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_APPLICATION));
            }
        };
    }

    @Override
    public long getFlagsRaw()
    {
        return flags;
    }
}
