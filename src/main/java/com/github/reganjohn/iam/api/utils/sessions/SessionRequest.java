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

import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.entities.Session;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.UUID;

public interface SessionRequest<R extends SessionRequest<R>> extends SessionData
{
    @Nonnull
    R setUserId(@Nonnull UUID userId);

    @Nonnull
    R setSessionId(@Nonnull UUID sessionId);

    @Nonnull
    R setUserAgent(@Nullable String userAgent);

    @Nonnull
    R setAccessEntry(@Nonnull AccessEntryData accessEntry);

    @Nonnull
    R setSessionFlags(long flags);

    @Nonnull
    R setThumbprint(@Nonnull String thumbprint);

    @Nonnull
    default R applySession(@Nonnull Session session)
    {
        Checks.notNull(session, "Session");
        return setUserId(session.getUserId())
                .setSessionId(session.getUniqueId())
                .setUserAgent(session.getUserAgent())
                .setSessionFlags(session.getFlagsRaw())
                .setThumbprint(session.getThumbprint());
    }
}
