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

import javax.annotation.Nonnull;
import java.time.OffsetDateTime;
import java.util.UUID;

public class PermissionOverrideImpl implements PermissionOverride
{
    private final IAM api;
    private final UUID userId;
    private final UUID applicationId;
    private final int rawPermissions;
    private final OffsetDateTime createdAt;
    private final OffsetDateTime updatedAt;

    public PermissionOverrideImpl(@Nonnull IAM api, @Nonnull UUID userId, @Nonnull UUID applicationId,
                                  int rawPermissions, @Nonnull OffsetDateTime createdAt,
                                  @Nonnull OffsetDateTime updatedAt)
    {
        this.api = api;
        this.userId = userId;
        this.applicationId = applicationId;
        this.rawPermissions = rawPermissions;
        this.createdAt = createdAt;
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
    public UUID getApplicationId()
    {
        return applicationId;
    }

    @Nonnull
    @Override
    public OffsetDateTime getTimeCreated()
    {
        return createdAt;
    }

    @Nonnull
    @Override
    public OffsetDateTime getTimeUpdated()
    {
        return updatedAt;
    }

    @Override
    public int getPermissionsRaw()
    {
        return rawPermissions;
    }

    @Override
    public boolean hasPermission(@Nonnull Permission... permissions)
    {
        for (Permission perm : permissions)
        {
            int rawValue = perm.getRawValue();
            if ((rawPermissions & rawValue) != rawValue)
            {
                return false;
            }
        }
        return true;
    }
}
