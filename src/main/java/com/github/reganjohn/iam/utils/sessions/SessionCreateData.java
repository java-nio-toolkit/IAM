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

package com.github.reganjohn.iam.utils.sessions;

import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;

import javax.annotation.Nonnull;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class SessionCreateData implements SessionData
{
    private final UUID sessionId;
    private final UUID userId;
    private final String userAgent;
    private final AccessEntryData entryData;
    private final int flags;
    private final String thumbprint;

    public SessionCreateData(@Nonnull UUID userId, @Nonnull UUID sessionId, @Nonnull String userAgent,
                             @Nonnull AccessEntryData entryData, int flags, @Nonnull String thumbprint)
    {
        this.sessionId = sessionId;
        this.userId = userId;
        this.userAgent = userAgent;
        this.entryData = entryData;
        this.flags = flags;
        this.thumbprint = thumbprint;
    }

    @Override
    public boolean isEmpty()
    {
        return toData().size() == 0;
    }

    @Nonnull
    public Map<String, Object> toMap()
    {
        Map<String, Object> map = new HashMap<>();
        map.put("user_id", userId);
        map.put("session_id", sessionId);
        map.put("flags", flags);
        map.put("user_agent", userAgent);
        map.put("alg", entryData.getAccessOption().getMode());
        map.put("kid", entryData.getUniqueId());
        map.put("kty", entryData.getType().name());
        map.put("usage", entryData.getUsage().name().toLowerCase());
        map.put("public_key", entryData.getPublicKey().getEncoded());
        map.put("thumbprint", thumbprint);
        return map;
    }

    @Nonnull
    @Override
    public DataObject toData()
    {
        return DataObject.empty()
                .put("user_id", userId)
                .put("session_id", sessionId)
                .put("flags", flags)
                .toData();
    }
}
