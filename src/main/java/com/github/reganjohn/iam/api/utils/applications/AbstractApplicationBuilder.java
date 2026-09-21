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
import com.github.reganjohn.iam.api.entities.Application;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@SuppressWarnings("unchecked")
public abstract class AbstractApplicationBuilder<T, R extends AbstractApplicationBuilder<T, R>> implements ApplicationRequest<R>
{
    protected UUID ownerId;
    protected UUID uniqueId;
    protected String name;
    protected String description;
    protected String iconId;
    protected String origin;
    protected long flags;
    protected final List<String> redirectUris = new ArrayList<>(Application.MAX_URL_COUNT);

    protected AbstractApplicationBuilder() {}

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
        Checks.notLonger(name, Application.MAX_NAME_LENGTH, "Name");
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
    public R setDescription(@Nullable String description)
    {
        if (description != null)
            Checks.notLonger(description, Application.MAX_DESCRIPTION_LENGTH, "Description");
        this.description = description;
        return (R) this;
    }

    @Nullable
    @Override
    public String getDescription()
    {
        return description;
    }

    @Nonnull
    @Override
    public R setIconId(@Nullable String iconId)
    {
        if (iconId != null)
            Checks.notLonger(iconId, Application.ICON_CID_MAX_LENGTH, "Icon ID");
        this.iconId = iconId;
        return (R) this;
    }

    @Nullable
    @Override
    public String getIconId()
    {
        return iconId;
    }

    @Nonnull
    @Override
    public R setOrigin(@Nonnull String origin)
    {
        Checks.notEmpty(origin, "Origin");
        this.origin = origin;
        return (R) this;
    }

    @Nonnull
    @Override
    public String getOrigin()
    {
        return origin;
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
    public R setRedirectUris(@Nonnull Collection<String> redirectUris)
    {
        Checks.noneNull(redirectUris, "Redirect URIs");
        Checks.notEmpty(redirectUris, "Redirect URIs");
        Checks.check(redirectUris.size() <= Application.MAX_URL_COUNT,
                "Cannot set more than %d redirect URIs", Application.MAX_URL_COUNT);
        this.redirectUris.clear();
        this.redirectUris.addAll(redirectUris);
        return (R) this;
    }

    @Nonnull
    @Override
    public List<String> getRedirectUris()
    {
        return Collections.unmodifiableList(redirectUris);
    }

    public abstract boolean isEmpty();

    public abstract boolean isValid();

    @Nonnull
    public abstract T build();

    @Nonnull
    public R clear()
    {
        this.ownerId = null;
        this.uniqueId = null;
        this.name = null;
        this.description = null;
        this.iconId = null;
        this.origin = null;
        this.flags = 0;
        this.redirectUris.clear();
        return (R) this;
    }
}
