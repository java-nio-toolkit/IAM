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
import com.github.reganjohn.iam.api.entities.Session;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.EnumSet;
import java.util.UUID;

public interface SessionData
{
    @Nonnull
    UUID getUserId();

    @Nonnull
    UUID getSessionId();

    @Nullable
    String getUserAgent();

    @Nonnull
    AccessEntryData getAccessEntry();

    long getRawSessionFlags();

    @Nonnull
    default EnumSet<Session.SessionFlag> getSessionFlags()
    {
        return Session.SessionFlag.getFlags(getRawSessionFlags());
    }

    @Nonnull
    String getThumbprint();
}
