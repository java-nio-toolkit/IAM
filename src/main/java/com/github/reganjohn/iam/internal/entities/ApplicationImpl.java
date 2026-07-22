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

import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.IAM;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.entities.ApplicationInfo;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.internal.interactions.InteractionImpl;
import com.reganjohn.jact.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionContextActionImpl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class ApplicationImpl implements Application
{
    private final IAMImpl api;
    private final UUID id;
    private final UUID ownerId;
    private final String name;
    private final String description;
    private final int flags;
    private final List<String> redirectUris;

    public ApplicationImpl(@Nonnull IAMImpl api, @Nonnull UUID id, @Nonnull UUID ownerId, @Nonnull String name,
                           @Nullable String description, int flags, @Nonnull List<String> redirectUris)
    {
        this.api = api;
        this.id = id;
        this.ownerId = ownerId;
        this.name = name;
        this.description = description;
        this.flags = flags;
        this.redirectUris = redirectUris;
    }

    @Nonnull
    @Override
    public IAM getIAM()
    {
        return api;
    }

    @Nonnull
    @Override
    public UUID getUniqueId()
    {
        return id;
    }

    @Nonnull
    @Override
    public UUID getOwnerId()
    {
        return ownerId;
    }

    @Nonnull
    @Override
    public String getName()
    {
        return name;
    }

    @Nullable
    @Override
    public String getDescription()
    {
        return description;
    }

    @Nonnull
    @Override
    public List<String> getRedirectUris()
    {
        return Collections.unmodifiableList(redirectUris);
    }

    @Override
    public int getFlagsRaw()
    {
        return flags;
    }
}
