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

import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.entities.Webhook;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.time.OffsetDateTime;
import java.util.UUID;

@SuppressWarnings("unchecked")
public abstract class AbstractWebhookBuilder<T, R extends AbstractWebhookBuilder<T, R>> implements WebhookRequest<R>
{
    protected UUID uniqueId;
    protected String name;
    protected UUID ownerId;
    protected String avatarId;
    protected String url;
    protected OffsetDateTime timeUpdated;
    protected long flags;
    protected long scopes;

    protected AbstractWebhookBuilder() {}

    @Nonnull
    @Override
    public R setUniqueId(@Nonnull UUID uniqueId)
    {
        Checks.notNull(uniqueId, "Unique ID");
        this.uniqueId = uniqueId;
        return (R) this;
    }

    @Nonnull
    @Override
    public UUID getUniqueId()
    {
        return uniqueId;
    }

    @Nonnull
    @Override
    public R setName(@Nonnull String name)
    {
        Checks.notEmpty(name, "Name");
        Checks.notLonger(name, Webhook.MAX_NAME_LENGTH, "Name");
        this.name = name;
        return (R) this;
    }

    @Nonnull
    @Override
    public String getName()
    {
        return name;
    }

    @Nonnull
    @Override
    public R setOwnerId(@Nonnull UUID ownerId)
    {
        Checks.notNull(ownerId, "Owner ID");
        this.ownerId = ownerId;
        return (R) this;
    }

    @Nonnull
    @Override
    public UUID getOwnerId()
    {
        return ownerId;
    }

    @Nonnull
    @Override
    public R setAvatarId(@Nullable String avatarId)
    {
        if (avatarId != null)
            Checks.notLonger(avatarId, Webhook.ICON_CID_MAX_LENGTH, "Avatar ID");
        this.avatarId = avatarId;
        return (R) this;
    }

    @Nullable
    @Override
    public String getAvatarId()
    {
        return avatarId;
    }

    @Nonnull
    @Override
    public R setUrl(@Nonnull String url)
    {
        Checks.notEmpty(url, "URL");
        this.url = url;
        return (R) this;
    }

    @Nonnull
    @Override
    public String getUrl()
    {
        return url;
    }

    @Nonnull
    @Override
    public R setTimeUpdated(@Nonnull OffsetDateTime timeUpdated)
    {
        Checks.notNull(timeUpdated, "Time Updated");
        this.timeUpdated = timeUpdated;
        return (R) this;
    }

    @Nonnull
    @Override
    public OffsetDateTime getTimeUpdated()
    {
        return timeUpdated;
    }

    @Nonnull
    @Override
    public R setFlags(long flags)
    {
        this.flags = flags;
        return (R) this;
    }

    @Override
    public long getFlagsRaw()
    {
        return flags;
    }

    @Nonnull
    @Override
    public R setScopes(long scopes)
    {
        this.scopes = scopes;
        return (R) this;
    }

    @Override
    public long getScopesRaw()
    {
        return scopes;
    }

    public abstract boolean isEmpty();

    public abstract boolean isValid();

    @Nonnull
    public abstract T build();

    @Nonnull
    public R clear()
    {
        this.uniqueId = null;
        this.name = null;
        this.ownerId = null;
        this.avatarId = null;
        this.url = null;
        this.timeUpdated = null;
        this.flags = 0;
        this.scopes = 0;
        return (R) this;
    }
}
