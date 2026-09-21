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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.time.OffsetDateTime;
import java.util.UUID;

public class WebhookEditBuilder extends AbstractWebhookBuilder<WebhookEditData, WebhookEditBuilder>
        implements WebhookEditRequest<WebhookEditBuilder>
{
    protected static final int UNIQUE_ID = 1;
    protected static final int NAME = 1 << 1;
    protected static final int OWNER_ID = 1 << 2;
    protected static final int AVATAR_ID = 1 << 3;
    protected static final int URL = 1 << 4;
    protected static final int TIME_UPDATED = 1 << 5;
    protected static final int FLAGS = 1 << 6;
    protected static final int SCOPES = 1 << 7;

    private boolean replace = false;
    private int configuredFields = 0;

    public WebhookEditBuilder() {}

    @Nonnull
    @Override
    public WebhookEditBuilder setUniqueId(@Nonnull UUID uniqueId)
    {
        super.setUniqueId(uniqueId);
        configuredFields |= UNIQUE_ID;
        return this;
    }

    @Nonnull
    @Override
    public WebhookEditBuilder setName(@Nonnull String name)
    {
        super.setName(name);
        configuredFields |= NAME;
        return this;
    }

    @Nonnull
    @Override
    public WebhookEditBuilder setOwnerId(@Nonnull UUID ownerId)
    {
        super.setOwnerId(ownerId);
        configuredFields |= OWNER_ID;
        return this;
    }

    @Nonnull
    @Override
    public WebhookEditBuilder setAvatarId(@Nullable String avatarId)
    {
        super.setAvatarId(avatarId);
        configuredFields |= AVATAR_ID;
        return this;
    }

    @Nonnull
    @Override
    public WebhookEditBuilder setUrl(@Nonnull String url)
    {
        super.setUrl(url);
        configuredFields |= URL;
        return this;
    }

    @Nonnull
    @Override
    public WebhookEditBuilder setTimeUpdated(@Nonnull OffsetDateTime timeUpdated)
    {
        super.setTimeUpdated(timeUpdated);
        configuredFields |= TIME_UPDATED;
        return this;
    }

    @Nonnull
    @Override
    public WebhookEditBuilder setFlags(long flags)
    {
        super.setFlags(flags);
        configuredFields |= FLAGS;
        return this;
    }

    @Nonnull
    @Override
    public WebhookEditBuilder setScopes(long scopes)
    {
        super.setScopes(scopes);
        configuredFields |= SCOPES;
        return this;
    }

    @Nonnull
    @Override
    public WebhookEditBuilder setReplace(boolean isReplace)
    {
        this.replace = isReplace;
        return this;
    }

    @Override
    public boolean isReplace()
    {
        return replace;
    }

    @Nonnull
    @Override
    public WebhookEditBuilder applyData(@Nonnull WebhookEditData data)
    {
        Checks.notNull(data, "WebhookEditData");
        this.configuredFields |= data.getConfiguredFields();
        this.replace |= data.isReplace();

        if (data.isSet(UNIQUE_ID))
            setUniqueId(data.getUniqueId());
        if (data.isSet(NAME))
            setName(data.getName());
        if (data.isSet(OWNER_ID))
            setOwnerId(data.getOwnerId());
        if (data.isSet(AVATAR_ID))
            setAvatarId(data.getAvatarId());
        if (data.isSet(URL))
            setUrl(data.getUrl());
        if (data.isSet(TIME_UPDATED))
            setTimeUpdated(data.getTimeUpdated());
        if (data.isSet(FLAGS))
            setFlags(data.getFlagsRaw());
        if (data.isSet(SCOPES))
            setScopes(data.getScopesRaw());

        return this;
    }

    @Override
    public boolean isEmpty()
    {
        return !replace && configuredFields == 0;
    }

    @Override
    public boolean isValid()
    {
        return true;
    }

    @Nonnull
    @Override
    public WebhookEditData build()
    {
        return new WebhookEditData(configuredFields, replace, uniqueId, name, ownerId, avatarId, url, timeUpdated, flags, scopes);
    }

    @Nonnull
    @Override
    public WebhookEditBuilder clear()
    {
        this.configuredFields = 0;
        this.replace = false;
        return super.clear();
    }
}
