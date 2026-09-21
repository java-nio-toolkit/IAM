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

import com.github.adamorgan.jnt.internal.utils.Checks;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.UUID;

public class ApplicationEditBuilder extends AbstractApplicationBuilder<ApplicationEditData, ApplicationEditBuilder>
        implements ApplicationEditRequest<ApplicationEditBuilder>
{
    protected static final int OWNER_ID = 1;
    protected static final int UNIQUE_ID = 1 << 1;
    protected static final int NAME = 1 << 2;
    protected static final int DESCRIPTION = 1 << 3;
    protected static final int ICON_ID = 1 << 4;
    protected static final int ORIGIN = 1 << 5;
    protected static final int FLAGS = 1 << 6;
    protected static final int REDIRECT_URIS = 1 << 7;

    private boolean replace = false;
    private int configuredFields = 0;

    public ApplicationEditBuilder() {}

    @Nonnull
    @Override
    public ApplicationEditBuilder setOwnerId(@Nonnull UUID ownerId)
    {
        super.setOwnerId(ownerId);
        configuredFields |= OWNER_ID;
        return this;
    }

    @Nonnull
    @Override
    public ApplicationEditBuilder setUniqueId(@Nonnull UUID uniqueId)
    {
        super.setUniqueId(uniqueId);
        configuredFields |= UNIQUE_ID;
        return this;
    }

    @Nonnull
    @Override
    public ApplicationEditBuilder setName(@Nonnull String name)
    {
        super.setName(name);
        configuredFields |= NAME;
        return this;
    }

    @Nonnull
    @Override
    public ApplicationEditBuilder setDescription(@Nullable String description)
    {
        super.setDescription(description);
        configuredFields |= DESCRIPTION;
        return this;
    }

    @Nonnull
    @Override
    public ApplicationEditBuilder setIconId(@Nullable String iconId)
    {
        super.setIconId(iconId);
        configuredFields |= ICON_ID;
        return this;
    }

    @Nonnull
    @Override
    public ApplicationEditBuilder setOrigin(@Nonnull String origin)
    {
        super.setOrigin(origin);
        configuredFields |= ORIGIN;
        return this;
    }

    @Nonnull
    @Override
    public ApplicationEditBuilder setFlags(long flags)
    {
        super.setFlags(flags);
        configuredFields |= FLAGS;
        return this;
    }

    @Nonnull
    @Override
    public ApplicationEditBuilder setRedirectUris(@Nonnull Collection<String> redirectUris)
    {
        super.setRedirectUris(redirectUris);
        configuredFields |= REDIRECT_URIS;
        return this;
    }

    @Nonnull
    @Override
    public ApplicationEditBuilder setReplace(boolean isReplace)
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
    public ApplicationEditBuilder applyData(@Nonnull ApplicationEditData data)
    {
        Checks.notNull(data, "ApplicationEditData");
        this.configuredFields |= data.getConfiguredFields();
        this.replace |= data.isReplace();

        if (data.isSet(OWNER_ID))
            setOwnerId(data.getOwnerId());
        if (data.isSet(UNIQUE_ID))
            setUniqueId(data.getUniqueId());
        if (data.isSet(NAME))
            setName(data.getName());
        if (data.isSet(DESCRIPTION))
            setDescription(data.getDescription());
        if (data.isSet(ICON_ID))
            setIconId(data.getIconId());
        if (data.isSet(ORIGIN))
            setOrigin(data.getOrigin());
        if (data.isSet(FLAGS))
            setFlags(data.getFlagsRaw());
        if (data.isSet(REDIRECT_URIS))
            setRedirectUris(data.getRedirectUris());

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
    public ApplicationEditData build()
    {
        return new ApplicationEditData(configuredFields, replace, ownerId, uniqueId, name, description, iconId, origin, flags, new ArrayList<>(redirectUris));
    }

    @Nonnull
    @Override
    public ApplicationEditBuilder clear()
    {
        this.configuredFields = 0;
        this.replace = false;
        return super.clear();
    }
}
