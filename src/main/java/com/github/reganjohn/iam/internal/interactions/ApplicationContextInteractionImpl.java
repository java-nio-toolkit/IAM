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


import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.github.reganjohn.iam.internal.IAMImpl;

import javax.annotation.Nonnull;
import java.time.OffsetDateTime;
import java.util.UUID;

public class ApplicationContextInteractionImpl implements ApplicationContextInteraction
{
    private final IAMImpl api;
    private final UUID ownerId;
    private final UUID applicationId;
    private final UUID interactionId;
    private final OffsetDateTime expiresAt;
    private final int rawPermissions;
    private final String redirectUri;

    public ApplicationContextInteractionImpl(@Nonnull IAMImpl api, @Nonnull UUID ownerId, @Nonnull UUID applicationId,
                                             @Nonnull UUID interactionId, @Nonnull OffsetDateTime expiresAt,
                                             int permissions, @Nonnull String uri)
    {
        this.api = api;
        this.ownerId = ownerId;
        this.applicationId = applicationId;
        this.interactionId = interactionId;
        this.expiresAt = expiresAt;
        this.rawPermissions = permissions;
        this.redirectUri = uri;
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
        return interactionId;
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
    public OffsetDateTime getTimeExpiresAt()
    {
        return expiresAt;
    }

    @Override
    public int getPermissionsRaw()
    {
        return rawPermissions;
    }

    @Nonnull
    @Override
    public String getRedirectUri()
    {
        return redirectUri;
    }
}
