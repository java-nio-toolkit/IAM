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

package com.github.reganjohn.iam.api.utils.users;

import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.utils.sessions.SessionCreateData;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class UserCreateBuilder extends AbstractUserBuilder<UserCreateData, UserCreateBuilder>
        implements UserCreateRequest<UserCreateBuilder>
{
    private SessionCreateData session;

    public UserCreateBuilder() {}

    @Nonnull
    @Override
    public UserCreateBuilder setSession(@Nonnull SessionCreateData session)
    {
        Checks.notNull(session, "Session");
        this.session = session;
        return this;
    }

    @Nullable
    @Override
    public SessionCreateData getSession()
    {
        return session;
    }

    @Override
    public boolean isEmpty()
    {
        return userId == null && name == null && session == null;
    }

    @Override
    public boolean isValid()
    {
        return userId != null && name != null && session != null;
    }

    @Nonnull
    @Override
    public UserCreateData build()
    {
        if (userId == null)
            throw new IllegalStateException("Cannot build a User without a user ID");
        if (name == null)
            throw new IllegalStateException("Cannot build a User without a name");
        if (session == null)
            throw new IllegalStateException("Cannot build a User without a session");

        return new UserCreateData(userId, name, avatarId, flags, session);
    }

    @Nonnull
    @Override
    public UserCreateBuilder clear()
    {
        this.session = null;
        return super.clear();
    }
}
