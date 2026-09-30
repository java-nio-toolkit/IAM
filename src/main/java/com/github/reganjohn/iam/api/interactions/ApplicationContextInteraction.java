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

package com.github.reganjohn.iam.api.interactions;

import com.github.adamorgan.jnt.api.entities.IUnique;
import com.github.reganjohn.iam.api.Permission;
import com.github.reganjohn.iam.internal.IAMImpl;

import javax.annotation.Nonnull;
import java.time.OffsetDateTime;
import java.util.EnumSet;
import java.util.UUID;

public interface ApplicationContextInteraction extends IUnique
{
    @Nonnull
    IAMImpl getIAM();

    @Nonnull
    UUID getOwnerId();

    @Nonnull
    UUID getApplicationId();

    @Nonnull
    OffsetDateTime getTimeExpiresAt();

    long getPermissionsRaw();

    @Nonnull
    default EnumSet<Permission> getPermissions()
    {
        return Permission.getPermissions(getPermissionsRaw());
    }

    @Nonnull
    String getRedirectUri();

    @Nonnull
    String getClientNonce();

    @Nonnull
    String getFinishNonce();

    @Nonnull
    String getMethodHash();

    @Nonnull
    String getUri();

    @Nonnull
    String hash();

    @Nonnull
    String getThumbprint();
}
