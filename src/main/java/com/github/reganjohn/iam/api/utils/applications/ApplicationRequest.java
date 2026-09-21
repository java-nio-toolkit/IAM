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

package com.github.reganjohn.iam.api.utils.applications;

import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.entities.Application;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collection;
import java.util.UUID;

public interface ApplicationRequest<R extends ApplicationRequest<R>> extends ApplicationData
{
    @Nonnull
    R setOwnerId(@Nonnull UUID ownerId);

    @Nonnull
    R setUniqueId(@Nonnull UUID uniqueId);

    @Nonnull
    R setName(@Nonnull String name);

    @Nonnull
    R setDescription(@Nullable String description);

    @Nonnull
    R setIconId(@Nullable String iconId);

    @Nonnull
    R setOrigin(@Nonnull String origin);

    @Nonnull
    R setFlags(long flags);

    @Nonnull
    R setRedirectUris(@Nonnull Collection<String> redirectUris);

    @Nonnull
    default R applyApplication(@Nonnull Application application)
    {
        Checks.notNull(application, "Application");
        return setOwnerId(application.getOwnerId())
                .setUniqueId(application.getUniqueId())
                .setName(application.getName())
                .setDescription(application.getDescription())
                .setIconId(application.getIconId())
                .setOrigin(application.getOrigin())
                .setFlags(application.getFlagsRaw())
                .setRedirectUris(application.getRedirectUris());
    }
}
