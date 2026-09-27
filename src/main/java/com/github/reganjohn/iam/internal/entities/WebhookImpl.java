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

import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.reganjohn.iam.api.IAM;
import com.github.reganjohn.iam.api.entities.Webhook;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.internal.requests.objaction.InteractionContextActionImpl;
import com.reganjohn.c4j.internal.utils.InteractionUtil;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.UUID;

public class WebhookImpl implements Webhook
{
    private final IAM api;
    private final UUID id;
    private final String name;
    private final UUID userId;
    private final String avatarId;
    private final long scopes;
    private final String url;
    private final OffsetDateTime updatedAt;
    private final long flags;

    public WebhookImpl(@Nonnull IAM api, @Nonnull UUID id, @Nonnull String name, @Nonnull UUID ownerId, @Nullable String avatarId,
                       @Nonnull String url, @Nonnull OffsetDateTime updatedAt, long flags, long scopes)
    {
        this.api = api;
        this.id = id;
        this.name = name;
        this.userId = ownerId;
        this.avatarId = avatarId;
        this.url = url;
        this.updatedAt = updatedAt;
        this.flags = flags;
        this.scopes = scopes;
    }

    @Nonnull
    @Override
    public UUID getUniqueId()
    {
        return id;
    }

    @Nonnull
    @Override
    public IAM getIAM()
    {
        return api;
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
    public InteractionCallbackAction<Void> delete()
    {
        long flags = getFlagsRaw() | WebhookFlag.DELETED.getRawValue();
        return new InteractionContextActionImpl<>(api.getJCA(), "UPDATE users.webhooks SET flags = ? WHERE owner_id = ? AND webhook_id = ? IF EXISTS", Arrays.asList(flags, userId, id))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponse response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (InteractionUtil.isDone(array))
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_WEBHOOK));
            }
        };
    }

    @Nonnull
    @Override
    public DataObject toData()
    {
        return DataObject.empty()
                .put("owner_id", getOwnerId())
                .put("webhook_id", getUniqueId())
                .put("name", getName())
                .put("avatar_id", getAvatarId())
                .put("url", getUrl())
                .put("scopes", getScopesRaw())
                .put("flags", getFlagsRaw())
                .put("updated_at", getTimeUpdated())
                .toData();
    }
}
