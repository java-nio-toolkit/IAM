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

import com.github.reganjohn.iam.api.entities.Application;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;

public interface ApplicationData
{
    @Nonnull
    UUID getOwnerId();

    @Nonnull
    UUID getUniqueId();

    @Nonnull
    String getName();

    @Nullable
    String getDescription();

    @Nullable
    String getIconId();

    @Nonnull
    String getOrigin();

    long getFlagsRaw();

    @Nonnull
    default EnumSet<Application.ApplicationFlag> getApplicationFlags()
    {
        return Application.ApplicationFlag.getFlags(getFlagsRaw());
    }

    @Nonnull
    List<String> getRedirectUris();
}
