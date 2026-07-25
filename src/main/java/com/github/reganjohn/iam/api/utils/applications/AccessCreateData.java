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
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.reganjohn.jact.api.interactions.context.InteractionMapping;

import javax.annotation.Nonnull;
import java.util.UUID;

public class AccessCreateData implements ApplicationData
{
    private final UUID userId;
    private final UUID applicationId;
    private final AccessEntryData entryData;
    private final String thumbprint;

    public AccessCreateData(@Nonnull UUID userId, @Nonnull UUID applicationId, @Nonnull AccessEntryData data,
                            @Nonnull String thumbprint)
    {
        this.userId = userId;
        this.applicationId = applicationId;
        this.entryData = data;
        this.thumbprint = thumbprint;
    }

    @Nonnull
    public InteractionMapping toMap()
    {
        return new InteractionMapping.Builder()
                .put("user_id", userId)
                .put("application_id", applicationId)
                .put("alg", entryData.getAccessOption().getMode())
                .put("kid", entryData.getName())
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
                .put("alg", entryData.getAccessOption().getMode())
                .put("kid", entryData.getName())
                .put("kty", entryData.getType().name())
                .put("usage", entryData.getUsage().name().toLowerCase())
                .put("public_key", entryData.getPublicKey().getEncoded())
                .put("thumbprint", thumbprint)
                .toData();
    }
}
