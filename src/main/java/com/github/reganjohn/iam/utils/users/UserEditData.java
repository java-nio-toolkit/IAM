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

package com.github.reganjohn.iam.utils.users;

import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.internal.utils.Helpers;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;

public class UserEditData implements UserData
{
    private final UUID id;
    private final String name;
    private final int flags;

    public UserEditData(@Nonnull UUID id, String name, int flags)
    {
        this.id = id;
        this.name = name;
        this.flags = flags;
    }

    @Nonnull
    @Override
    public UUID getUniqueId()
    {
        return id;
    }

    @Nullable
    @Override
    public String getName()
    {
        return name;
    }

    @Override
    public int getFlagsRaw()
    {
        return flags;
    }

    @Override
    public boolean isEmpty()
    {
        return toData().size() == 0;
    }

    @Nonnull
    public Map<String, Object> toMap()
    {
        Map<String, Object> map = new HashMap<>(Collections.singletonMap("user_id", id));
        if (Helpers.nonEmpty(name))
            map.put("username", name);
        if (flags != 0)
            map.put("flags", flags);
        return map;
    }

    @Nonnull
    @Override
    public DataObject toData()
    {
        DataObject data = DataObject.empty();
        if (Helpers.nonEmpty(name))
            data.put("username", name);
        if (flags != 0)
            data.put("flags", flags);
        return data;
    }
}
