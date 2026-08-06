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

import com.github.reganjohn.iam.api.IAM;
import com.github.reganjohn.iam.api.Permission;
import com.github.reganjohn.iam.api.entities.PermissionOverride;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.internal.interactions.InteractionImpl;
import com.reganjohn.jact.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionContextActionImpl;
import com.reganjohn.jact.internal.utils.InteractionUtil;

import javax.annotation.Nonnull;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.UUID;

public class PermissionOverrideImpl implements PermissionOverride
{
    private final IAM api;
    private final UUID userId;
    private final UUID ownerId;
    private final UUID applicationId;
    private final long rawPermissions;
    private final long flags;
    private final OffsetDateTime updatedAt;

    public PermissionOverrideImpl(@Nonnull IAM api, @Nonnull UUID userId, @Nonnull UUID ownerId,
                                  @Nonnull UUID applicationId, long rawPermissions, long flags,
                                  @Nonnull OffsetDateTime updatedAt)
    {
        this.api = api;
        this.userId = userId;
        this.ownerId = ownerId;
        this.applicationId = applicationId;
        this.rawPermissions = rawPermissions;
        this.flags = flags;
        this.updatedAt = updatedAt;
    }

    @Nonnull
    @Override
    public IAM getIAM()
    {
        return api;
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
    public OffsetDateTime getTimeUpdated()
    {
        return updatedAt;
    }

    @Override
    public long getPermissionsRaw()
    {
        return rawPermissions;
    }

    @Override
    public long getFlagsRaw()
    {
        return flags;
    }

    @Override
    public boolean hasPermission(@Nonnull Permission... permissions)
    {
        for (Permission perm : permissions)
        {
            long rawValue = perm.getRawValue();
            if ((rawPermissions & rawValue) != rawValue)
            {
                return false;
            }
        }
        return true;
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<Void> delete()
    {
        long flags = getFlagsRaw() | EntitlementFlag.DELETED.getRawValue();
        return new InteractionContextActionImpl<>(api.getJACT(), "UPDATE users.entitlements SET flags = ? WHERE user_id = ? AND application_id = ?", Arrays.asList(flags, userId, applicationId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> interaction,
                                      @Nonnull BufferArray array)
            {
                if (InteractionUtil.isDone(array))
                    interaction.onSuccess(null);
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_ENTITLEMENT));
            }
        };
    }
}
