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

package com.github.reganjohn.iam.internal.interactions;


import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.interactions.ApplicationCallbackResponse;
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
import java.util.UUID;

public class ApplicationCallbackResponseImpl implements ApplicationCallbackResponse
{
    private final IAMImpl api;
    private final UUID userId;
    private final UUID ownerId;
    private final UUID applicationId;
    private final UUID interactionId;
    private final long rawPermissions;
    private final String reference;
    private final String continueHash;
    private final String clientThumbprint;
    private final String userThumbprint;
    private final String label;
    private final boolean denied;

    public ApplicationCallbackResponseImpl(@Nonnull IAMImpl api, @Nonnull UUID userId, @Nonnull UUID ownerId,
                                           @Nonnull UUID applicationId, @Nonnull UUID interactionId, long permissions,
                                           @Nonnull String reference, @Nonnull String continueHash,
                                           @Nonnull String clientThumbprint, @Nonnull String userThumbprint,
                                           @Nullable String label, boolean denied)
    {
        this.api = api;
        this.userId = userId;
        this.ownerId = ownerId;
        this.applicationId = applicationId;
        this.interactionId = interactionId;
        this.rawPermissions = permissions;
        this.reference = reference;
        this.continueHash = continueHash;
        this.clientThumbprint = clientThumbprint;
        this.userThumbprint = userThumbprint;
        this.label = label;
        this.denied = denied;
    }

    @Nonnull
    @Override
    public IAMImpl getIAM()
    {
        return api;
    }

    @Nonnull
    @Override
    public UUID getInteractionId()
    {
        return interactionId;
    }

    @Nonnull
    @Override
    public UUID getUserId()
    {
        return userId;
    }

    @Nonnull
    @Override
    public UUID getOwnerId()
    {
        return ownerId;
    }

    @Nonnull
    @Override
    public UUID getApplicationId()
    {
        return applicationId;
    }

    @Override
    public long getPermissionsRaw()
    {
        return rawPermissions;
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Application> retrieveApplication()
    {
        return api.retrieveUserById(getOwnerId()).flatMap(user -> user.retrieveApplicationById(applicationId));
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<ApplicationCallbackResponse> delete()
    {
        return new InteractionContextActionImpl<>(api.getJCA(), "DELETE FROM integrations.responses WHERE application_id = ? AND interaction_id = ? IF EXISTS", Arrays.asList(getApplicationId(), getInteractionId()))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
                                      @Nonnull InteractionImpl<ApplicationCallbackResponse> interaction,
                                      @Nonnull BufferArray array)
            {
                if (InteractionUtil.isDone(array))
                    interaction.onSuccess(ApplicationCallbackResponseImpl.this);
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_INTERACTION));
            }
        };
    }

    @Nonnull
    @Override
    public String getInteractionReference()
    {
        return reference;
    }

    @Nonnull
    @Override
    public String getContinueHash()
    {
        return continueHash;
    }

    @Nonnull
    @Override
    public String getClientThumbprint()
    {
        return clientThumbprint;
    }

    @Nonnull
    @Override
    public String getThumbprint()
    {
        return userThumbprint;
    }

    @Nullable
    @Override
    public String getLabel()
    {
        return label;
    }

    @Override
    public boolean isDenied()
    {
        return denied;
    }
}
