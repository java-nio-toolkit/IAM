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

import javax.annotation.Nonnull;
import java.util.ArrayList;

public class ApplicationCreateBuilder extends AbstractApplicationBuilder<ApplicationCreateData, ApplicationCreateBuilder>
        implements ApplicationCreateRequest<ApplicationCreateBuilder>
{
    public ApplicationCreateBuilder() {}

    @Override
    public boolean isEmpty()
    {
        return ownerId == null && uniqueId == null && name == null && origin == null && redirectUris.isEmpty();
    }

    @Override
    public boolean isValid()
    {
        return ownerId != null && uniqueId != null && name != null && origin != null && !redirectUris.isEmpty();
    }

    @Nonnull
    @Override
    public ApplicationCreateData build()
    {
        if (ownerId == null)
            throw new IllegalStateException("Cannot build an Application without an owner ID");
        if (uniqueId == null)
            throw new IllegalStateException("Cannot build an Application without a unique ID");
        if (name == null)
            throw new IllegalStateException("Cannot build an Application without a name");
        if (origin == null)
            throw new IllegalStateException("Cannot build an Application without an origin");
        if (redirectUris.isEmpty())
            throw new IllegalStateException("Cannot build an Application without redirect URIs");

        return new ApplicationCreateData(ownerId, uniqueId, name, description, iconId, origin, flags, new ArrayList<>(redirectUris));
    }
}
