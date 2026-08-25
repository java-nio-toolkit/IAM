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

import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.reganjohn.iam.api.interactions.AccessContextInteraction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionContextActionImpl;

import javax.annotation.Nonnull;
import java.util.Arrays;
import java.util.UUID;

public class AccessContextInteractionImpl implements AccessContextInteraction
{
    private final IAMImpl api;
    private final UUID applicationId;
    private final UUID accessId;
    private final UUID userId;
    private final UUID ownerId;
    private final long flags;
    private final String thumbprint;

    public AccessContextInteractionImpl(@Nonnull IAMImpl api, @Nonnull UUID userId, @Nonnull UUID ownerId,
                                        @Nonnull UUID applicationId, @Nonnull UUID accessId, long flags, @Nonnull String thumbprint)
    {
        this.api = api;
        this.userId = userId;
        this.applicationId = applicationId;
        this.accessId = accessId;
        this.ownerId = ownerId;
        this.flags = flags;
        this.thumbprint = thumbprint;
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
        return accessId;
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

    @Nonnull
    @Override
    public String getThumbprint()
    {
        return thumbprint;
    }

    @Override
    public long getFlagsRaw()
    {
        return flags;
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<AccessEntryData> retrieveAccess()
    {
        return api.retrieveUserById(userId).flatMap(user -> user.retrieveAccessById(thumbprint));
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Void> revoke()
    {
        long flags = getFlagsRaw() | AccessContextInteraction.AccessContextFlag.DELETED.getRawValue();
        return new InteractionContextActionImpl<>(api.getJCA(), "UPDATE integrations.public_keys SET flags = ? WHERE user_id = ? AND application_id = ? AND access_id = ?", Arrays.asList(flags, userId, applicationId, accessId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> interaction,
                                      @Nonnull BufferArray array)
            {
                interaction.onSuccess(null);
            }
        };
    }
}
