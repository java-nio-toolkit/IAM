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

import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.entities.ApplicationContext;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class ApplicationContextImpl implements ApplicationContext
{
    private final IAMImpl api;
    private final Application application;
    private final List<String> thumbprints;

    public ApplicationContextImpl(@Nonnull IAMImpl api, @Nonnull Application application, @Nonnull List<String> thumbprints)
    {
        this.api = api;
        this.application = application;
        this.thumbprints = thumbprints;
    }

    @Nonnull
    @Override
    public IAMImpl getIAM()
    {
        return api;
    }

    @Nonnull
    @Override
    public UUID getUniqueId()
    {
        return application.getUniqueId();
    }

    @Nonnull
    @Override
    public Application getApplication()
    {
        return application;
    }

    @Nonnull
    @Override
    public List<String> getThumbprints()
    {
        return Collections.unmodifiableList(thumbprints);
    }

    @Nonnull
    @Override
    public InteractionCallbackAction<List<AccessEntryData>> retrieveAccessEntries()
    {
        Checks.notNull(application, "Application");
        return api.retrieveAccessEntries(application.getOwnerId(), getThumbprints());
    }
}
