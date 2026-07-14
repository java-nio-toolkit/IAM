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

import com.github.adamorgan.jnt.api.utils.UUIDv7;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.reganjohn.jact.api.interactions.context.InteractionMapping;
import com.reganjohn.jact.internal.interactions.context.InteractionMappingImpl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.UUID;

public class ApplicationCreateData implements ApplicationData
{
    private final UUID userId;
    private final UUID applicationId;
    private final String name;
    private final String description;
    private final AccessEntryData entryData;
    private final int flags;
    private final List<String> redirectUris;
    private final String thumbprint;

    public ApplicationCreateData(@Nonnull UUID userId, @Nonnull UUID applicationId, @Nonnull String name,
                                 @Nullable String description, @Nonnull AccessEntryData entryData, int flags,
                                 @Nullable List<String> redirectUris, @Nonnull String thumbprint)
    {
        this.userId = userId;
        this.applicationId = applicationId;
        this.name = name;
        this.description = description;
        this.entryData = entryData;
        this.flags = flags;
        this.redirectUris = redirectUris;
        this.thumbprint = thumbprint;
    }

    @Nonnull
    public InteractionMapping toMap()
    {
        return new InteractionMapping.Builder()
                .put("user_id", userId)
                .put("application_id", applicationId)
                .put("name", name)
                .put("description", description)
                .put("flags", flags)
                .put("redirect_uris", redirectUris)
                .put("kid", entryData.getName())
                .put("alg", entryData.getAccessOption().getMode())
                .put("kty", entryData.getType().name())
                .put("usage", entryData.getUsage().name().toLowerCase())
                .put("public_key", entryData.getPublicKey().getEncoded())
                .put("thumbprint", thumbprint)
                .build();
    }

    @Nonnull
    @Override
    public DataObject toData()
    {
        return DataObject.empty()
                .put("jwk", entryData.toData())
                .toData();
    }
}
