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

public interface ApplicationEditRequest<R extends ApplicationEditRequest<R>> extends ApplicationRequest<R>
{
    @Nonnull
    R setReplace(boolean isReplace);

    boolean isReplace();

    @Nonnull
    R applyData(@Nonnull ApplicationEditData data);

    @Nonnull
    default R applyCreateData(@Nonnull ApplicationCreateData data)
    {
        Checks.notNull(data, "ApplicationCreateData");
        return setReplace(true)
                .setOwnerId(data.getOwnerId())
                .setUniqueId(data.getUniqueId())
                .setName(data.getName())
                .setDescription(data.getDescription())
                .setIconId(data.getIconId())
                .setOrigin(data.getOrigin())
                .setFlags(data.getFlagsRaw())
                .setRedirectUris(data.getRedirectUris());
    }

    @Nonnull
    @Override
    default R applyApplication(@Nonnull Application application)
    {
        return ApplicationRequest.super.applyApplication(application).setReplace(true);
    }
}
