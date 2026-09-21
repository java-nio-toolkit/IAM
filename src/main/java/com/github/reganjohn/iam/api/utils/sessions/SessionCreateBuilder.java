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

import javax.annotation.Nonnull;

public class SessionCreateBuilder extends AbstractSessionBuilder<SessionCreateData, SessionCreateBuilder>
        implements SessionCreateRequest<SessionCreateBuilder>
{
    public SessionCreateBuilder() {}

    @Override
    public boolean isEmpty()
    {
        return userId == null && sessionId == null && accessEntry == null && thumbprint == null;
    }

    @Override
    public boolean isValid()
    {
        return userId != null && sessionId != null && accessEntry != null && thumbprint != null;
    }

    @Nonnull
    @Override
    public SessionCreateData build()
    {
        if (userId == null)
            throw new IllegalStateException("Cannot build a Session without a user ID");
        if (sessionId == null)
            throw new IllegalStateException("Cannot build a Session without a session ID");
        if (accessEntry == null)
            throw new IllegalStateException("Cannot build a Session without an access entry");
        if (thumbprint == null)
            throw new IllegalStateException("Cannot build a Session without a thumbprint");

        return new SessionCreateData(userId, sessionId, userAgent, accessEntry, flags, thumbprint);
    }
}
