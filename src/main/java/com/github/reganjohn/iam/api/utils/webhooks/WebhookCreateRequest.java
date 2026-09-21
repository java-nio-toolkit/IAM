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

public interface WebhookCreateRequest<R extends WebhookCreateRequest<R>> extends WebhookRequest<R>
{
    @Nonnull
    default R applyData(@Nonnull WebhookCreateData data)
    {
        Checks.notNull(data, "WebhookCreateData");
        return setUniqueId(data.getUniqueId())
                .setName(data.getName())
                .setOwnerId(data.getOwnerId())
                .setAvatarId(data.getAvatarId())
                .setUrl(data.getUrl())
                .setTimeUpdated(data.getTimeUpdated())
                .setFlags(data.getFlagsRaw())
                .setScopes(data.getScopesRaw());
    }
}
