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


import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.github.reganjohn.iam.internal.IAMImpl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.time.OffsetDateTime;
import java.util.UUID;

public class ApplicationContextInteractionImpl implements ApplicationContextInteraction
{
    private final IAMImpl api;
    private final UUID ownerId;
    private final UUID applicationId;
    private final UUID interactionId;
    private final OffsetDateTime expiresAt;
    private final long rawPermissions;
    private final String redirectUri;
    private final String clientNonce;
    private final String finishNonce;
    private final String hashMethod;
    private final String grantUri;
    private final String continueHash;
    private final DataObject accessRaw;
    private final String label;

    public ApplicationContextInteractionImpl(@Nonnull IAMImpl api, @Nonnull UUID ownerId, @Nonnull UUID applicationId,
                                             @Nonnull UUID interactionId, @Nonnull OffsetDateTime expiresAt,
                                             long permissions, @Nonnull String uri, @Nonnull String clientNonce,
                                             @Nonnull String finishNonce, @Nonnull String hashMethod,
                                             @Nonnull String grantUri, @Nonnull String continueHash,
                                             @Nonnull DataObject accessRaw, @Nullable String label)
    {
        this.api = api;
        this.ownerId = ownerId;
        this.applicationId = applicationId;
        this.interactionId = interactionId;
        this.expiresAt = expiresAt;
        this.rawPermissions = permissions;
        this.redirectUri = uri;
        this.clientNonce = clientNonce;
        this.finishNonce = finishNonce;
        this.hashMethod = hashMethod;
        this.grantUri = grantUri;
        this.continueHash = continueHash;
        this.accessRaw = accessRaw;
        this.label = label;
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
    public long getPermissionsRaw()
    {
        return rawPermissions;
    }

    @Nonnull
    @Override
    public String getRedirectUri()
    {
        return redirectUri;
    }
    @Nonnull
    @Override
    public String getClientNonce()
    {
        return clientNonce;
    }

    @Nonnull
    @Override
    public String getFinishNonce()
    {
        return finishNonce;
    }

    @Nonnull
    @Override
    public String getMethodHash()
    {
        return hashMethod;
    }

    @Nonnull
    @Override
    public String getUri()
    {
        return grantUri;
    }

    @Nonnull
    @Override
    public String hash()
    {
        return continueHash;
    }

    @Nonnull
    @Override
    public DataObject getAccessRaw()
    {
        return accessRaw;
    }

    @Nullable
    @Override
    public String getLabel()
    {
        return label;
    }
}
