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

package com.github.reganjohn.iam.api.utils.webhooks;

import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.reganjohn.jact.api.interactions.context.InteractionMapping;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

public class WebhookCreateData implements WebhookData
{
    private final UUID webhookId;
    private final String name;
    private final UUID userId;
    private final String avatarId;
    private final long scopes;
    private final String url;
    private final OffsetDateTime updatedAt;
    private final long flags;

    public WebhookCreateData(@Nonnull UUID id, @Nonnull String name, @Nonnull UUID userId, @Nullable String avatarId,
                             long scopes, @Nonnull String url, @Nonnull OffsetDateTime updatedAt, long flags)
    {
        this.webhookId = id;
        this.name = name;
        this.userId = userId;
        this.avatarId = avatarId;
        this.scopes = scopes;
        this.url = url;
        this.updatedAt = updatedAt;
        this.flags = flags;
    }

    @Nonnull
    @Override
    public UUID getUniqueId()
    {
        return webhookId;
    }

    @Nonnull
    @Override
    public String getName()
    {
        return name;
    }

    @Nonnull
    @Override
    public UUID getOwnerId()
    {
        return userId;
    }

    @Nullable
    @Override
    public String getAvatarId()
    {
        return avatarId;
    }

    @Nonnull
    @Override
    public String getUrl()
    {
        return url;
    }

    @Nonnull
    @Override
    public OffsetDateTime getTimeUpdated()
    {
        return updatedAt;
    }

    @Override
    public long getFlagsRaw()
    {
        return flags;
    }

    @Override
    public long getScopesRaw()
    {
        return scopes;
    }

    @Nonnull
    @Override
    public Map<String, Object> toMap()
    {
        return new InteractionMapping.Builder()
                .put("owner_id", userId)
                .put("webhook_id", webhookId)
                .put("name", name)
                .put("avatar_id", avatarId)
                .put("endpoint", url)
                .put("scopes", scopes)
                .put("flags", flags)
                .put("updated_at", updatedAt)
                .toMap();
    }

    @Nonnull
    @Override
    public DataObject toData()
    {
        return DataObject.fromMap(toMap());
    }
}
