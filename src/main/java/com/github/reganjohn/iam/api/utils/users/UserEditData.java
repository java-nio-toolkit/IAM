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
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;

public class UserEditData implements UserData
{
    private final UUID id;
    private String name;

    private Integer flags;

    public UserEditData(@Nonnull UUID id)
    {
        this.id = id;
    }

    @Nonnull
    @Override
    public UUID getUniqueId()
    {
        return id;
    }

    @Nullable
    public String getName()
    {
        return name;
    }

    @Nonnull
    public UserEditData setName(@Nonnull String name)
    {
        Checks.notEmpty(name, "Name");
        Checks.inRange(2, 32, "Name");
        this.name = name;
        return this;
    }

    @Nonnull
    public UserEditData setFlags(int flags)
    {
        this.flags = flags;
        return this;
    }

    @Nonnull
    public Map<String, Object> toMap()
    {
        Map<String, Object> map = new HashMap<>();
        map.put("user_id", id);
        if (Helpers.nonEmpty(name))
            map.put("username", name);
        return Collections.unmodifiableMap(map);
    }

    @Nonnull
    @Override
    public DataObject toData()
    {
        DataObject data = DataObject.empty();
        if (Helpers.nonEmpty(name))
            data.put("username", name);
        return data;
    }
}
