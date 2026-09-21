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

import javax.annotation.Nonnull;

public class WebhookCreateBuilder extends AbstractWebhookBuilder<WebhookCreateData, WebhookCreateBuilder>
        implements WebhookCreateRequest<WebhookCreateBuilder>
{
    public WebhookCreateBuilder() {}

    @Override
    public boolean isEmpty()
    {
        return uniqueId == null && name == null && ownerId == null && url == null;
    }

    @Override
    public boolean isValid()
    {
        return uniqueId != null && name != null && ownerId != null && url != null && timeUpdated != null;
    }

    @Nonnull
    @Override
    public WebhookCreateData build()
    {
        if (uniqueId == null)
            throw new IllegalStateException("Cannot build a Webhook without a unique ID");
        if (name == null)
            throw new IllegalStateException("Cannot build a Webhook without a name");
        if (ownerId == null)
            throw new IllegalStateException("Cannot build a Webhook without an owner ID");
        if (url == null)
            throw new IllegalStateException("Cannot build a Webhook without a URL");
        if (timeUpdated == null)
            throw new IllegalStateException("Cannot build a Webhook without a time updated");

        return new WebhookCreateData(uniqueId, name, ownerId, avatarId, scopes, url, timeUpdated, flags);
    }
}
