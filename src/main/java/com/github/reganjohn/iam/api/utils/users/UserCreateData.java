/*
 * Copyright 2026 Ada Morgan, John Regan and the JNT contributors
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

import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;

public class UserCreateData implements UserData
{
    private final UUID sessionId;
    private final UUID userId;
    private final String name;
    private final String userAgent;
    private final AccessEntryData entryData;
    private final int userFlags;
    private final int sessionFlags;
    private final String thumbprint;

    public UserCreateData(@Nonnull UUID userId, @Nonnull UUID sessionId, @Nonnull String name,
                          @Nullable String userAgent, @Nonnull AccessEntryData entryData,
                          int userFlags, int sessionFlags, @Nonnull String thumbprint)
    {
        this.sessionId = sessionId;
        this.userId = userId;
        this.name = name;
        this.userAgent = userAgent;
        this.entryData = entryData;
        this.userFlags = userFlags;
        this.sessionFlags = sessionFlags;
        this.thumbprint = thumbprint;
    }

    @Nonnull
    @Override
    public UUID getUniqueId()
    {
        return userId;
    }

    @Nonnull
    @Override
    public Map<String, Object> toMap()
    {
        Map<String, Object> data = new HashMap<>();
        data.put("user_id", userId);
        data.put("session_id", sessionId);
        data.put("username", name);
        data.put("user_flags", userFlags);
        data.put("user_agent", userAgent);
        data.put("alg", entryData.getAccessOption().getMode());
        data.put("kid", entryData.getName());
        data.put("kty", entryData.getType().name());
        data.put("session_flags", sessionFlags);
        data.put("usage", entryData.getUsage().name().toLowerCase());
        data.put("public_key", entryData.getPublicKey().getEncoded());
        data.put("thumbprint", thumbprint);
        return Collections.unmodifiableMap(data);
    }

    @Nonnull
    @Override
    public DataObject toData()
    {
        return DataObject.empty()
                .put("user_id", userId)
                .put("session_id", sessionId)
                .put("username", name)
                .toData();
    }
}
