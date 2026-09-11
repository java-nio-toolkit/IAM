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

import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.reganjohn.c4j.api.interactions.context.InteractionMapping;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class ApplicationEditData implements ApplicationData
{
    private final UUID userId;
    private final UUID applicationId;
    private final String name;
    private final String description;
    private final String iconId;
    private final String origin;
    private final long flags;
    private final List<String> redirectUris;

    public ApplicationEditData(@Nonnull UUID userId, @Nonnull UUID applicationId, @Nonnull String name,
                               @Nullable String description, @Nullable String iconId, @Nonnull String origin,
                               long flags, @Nonnull List<String> redirectUris)
    {
        this.userId = userId;
        this.applicationId = applicationId;
        this.name = name;
        this.description = description;
        this.iconId = iconId;
        this.origin = origin;
        this.flags = flags;
        this.redirectUris = redirectUris;
    }

    @Nonnull
    public Map<String, Object> toMap()
    {
        return new InteractionMapping.Builder()
                .put("user_id", userId)
                .put("application_id", applicationId)
                .put("name", name)
                .put("description", description)
                .put("origin", origin)
                .put("icon_id", iconId)
                .put("flags", flags)
                .put("redirect_uris", redirectUris)
                .toMap();
    }

    @Nonnull
    @Override
    public DataObject toData()
    {
        return DataObject.fromMap(toMap());
    }
}
