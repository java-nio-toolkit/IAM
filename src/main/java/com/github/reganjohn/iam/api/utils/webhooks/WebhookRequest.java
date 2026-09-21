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

public interface WebhookRequest<R extends WebhookRequest<R>> extends WebhookData
{
    @Nonnull
    R setUniqueId(@Nonnull UUID uniqueId);

    @Nonnull
    R setName(@Nonnull String name);

    @Nonnull
    R setOwnerId(@Nonnull UUID ownerId);

    @Nonnull
    R setAvatarId(@Nullable String avatarId);

    @Nonnull
    R setUrl(@Nonnull String url);

    @Nonnull
    R setTimeUpdated(@Nonnull OffsetDateTime timeUpdated);

    @Nonnull
    R setFlags(long flags);

    @Nonnull
    R setScopes(long scopes);

    @Nonnull
    default R applyWebhook(@Nonnull Webhook webhook)
    {
        Checks.notNull(webhook, "Webhook");
        return setUniqueId(webhook.getUniqueId())
                .setName(webhook.getName())
                .setOwnerId(webhook.getOwnerId())
                .setAvatarId(webhook.getAvatarId())
                .setUrl(webhook.getUrl())
                .setTimeUpdated(webhook.getTimeUpdated())
                .setFlags(webhook.getFlagsRaw())
                .setScopes(webhook.getScopesRaw());
    }
}
