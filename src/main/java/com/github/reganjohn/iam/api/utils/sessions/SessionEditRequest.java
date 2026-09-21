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

package com.github.reganjohn.iam.api.utils.sessions;

import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.entities.Session;

import javax.annotation.Nonnull;

public interface SessionEditRequest<R extends SessionEditRequest<R>> extends SessionRequest<R>
{
    @Nonnull
    R setReplace(boolean isReplace);

    boolean isReplace();

    @Nonnull
    R applyData(@Nonnull SessionEditData data);

    @Nonnull
    default R applyCreateData(@Nonnull SessionCreateData data)
    {
        Checks.notNull(data, "SessionCreateData");
        return setReplace(true)
                .setUserId(data.getUserId())
                .setSessionId(data.getSessionId())
                .setUserAgent(data.getUserAgent())
                .setAccessEntry(data.getAccessEntry())
                .setSessionFlags(data.getRawSessionFlags())
                .setThumbprint(data.getThumbprint());
    }

    @Nonnull
    @Override
    default R applySession(@Nonnull Session session)
    {
        return SessionRequest.super.applySession(session).setReplace(true);
    }
}
