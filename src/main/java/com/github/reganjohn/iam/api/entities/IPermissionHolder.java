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

package com.github.reganjohn.iam.api.entities;

import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.IAM;
import com.github.reganjohn.iam.api.Permission;

import javax.annotation.Nonnull;
import java.util.Collection;
import java.util.EnumSet;
import java.util.UUID;

public interface IPermissionHolder
{
    @Nonnull
    IAM getIAM();

    @Nonnull
    UUID getUserId();

    @Nonnull
    UUID getApplicationId();

    @Nonnull
    default EnumSet<Permission> getPermissions()
    {
        return Permission.getPermissions(getPermissionsRaw());
    }

    int getPermissionsRaw();

    boolean hasPermission(@Nonnull Permission... permissions);

    default boolean hasPermission(@Nonnull Collection<Permission> permissions)
    {
        Checks.notNull(permissions, "Permissions");
        return hasPermission(permissions.toArray(Permission.EMPTY_PERMISSIONS));
    }
}
