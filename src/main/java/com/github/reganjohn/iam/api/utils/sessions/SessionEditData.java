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

package com.github.reganjohn.iam.api.utils.sessions;

import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.internal.utils.Helpers;

import javax.annotation.Nonnull;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class SessionEditData implements SessionData
{
    private final UUID userId;
    private final UUID sessionId;
    private final int flags;
    private final String userAgent;

    public SessionEditData(UUID userId, UUID sessionId, int flags, String userAgent)
    {
        this.userId = userId;
        this.sessionId = sessionId;
        this.flags = flags;
        this.userAgent = userAgent;
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
        if (Helpers.nonEmpty(userAgent))
            map.put("user_agent", userAgent);
        if (flags != 0)
            map.put("flags", flags);
        return map;
    }

    @Nonnull
    @Override
    public DataObject toData()
    {
        DataObject data = DataObject.empty();
        if (Helpers.nonEmpty(userAgent))
            data.put("user_agent", userAgent);
        if (flags != 0)
            data.put("flags", flags);
        return data;
    }
}
