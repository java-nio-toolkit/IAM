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

package com.github.reganjohn.iam.internal.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.reganjohn.iam.api.Permission;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class PermissionUtil
{
    @Nonnull
    public static DataArray toDataArray(@Nonnull EnumSet<Permission> permissions)
    {
        Map<String, DataArray> map = new LinkedHashMap<>();
        for (Permission permission : permissions)
        {
            if (permission.equals(Permission.UNKNOWN))
                continue;
            String[] raw = permission.getName().split("\\.");
            map.computeIfAbsent(raw[0], ignored -> DataArray.empty()).add(raw[1]);
        }

        DataArray array = DataArray.empty();
        for (Map.Entry<String, DataArray> entry : map.entrySet())
        {
            DataObject data = DataObject.empty()
                    .put("type", entry.getKey())
                    .put("actions", entry.getValue())
                    .toData();
            array.add(data);
        }

        return array;
    }
    public static boolean isValid(@Nonnull DataArray array)
    {
        for (int i = 0; i < array.length(); i++)
        {
            if (!array.isType(i, DataType.OBJECT))
                return false;
            DataObject entry = array.getObject(i);
            if (!entry.isType("type", DataType.STRING) || !entry.isType("actions", DataType.ARRAY))
                return false;
            DataArray actions = entry.getArray("actions");
            for (int j = 0; j < actions.length(); j++)
            {
                if (!actions.isType(j, DataType.STRING) || !getNames().contains(entry.getString("type") + "." + actions.getString(j)))
                    return false;
            }
        }
        return true;
    }

    public static long toRaw(@Nonnull DataArray array)
    {
        if (!isValid(array))
            throw new IllegalArgumentException("Unknown access");
        long raw = 0;
        for (int i = 0; i < array.length(); i++)
        {
            DataObject entry = array.getObject(i);
            DataArray actions = entry.getArray("actions");
            for (int j = 0; j < actions.length(); j++)
                raw |= find(entry.getString("type") + "." + actions.getString(j)).getRawValue();
        }
        return raw;
    }

    @Nonnull
    private static Permission find(@Nonnull String name)
    {
        for (Permission permission : Permission.values())
        {
            if (permission != Permission.UNKNOWN && permission.getName().equals(name))
                return permission;
        }
        throw new IllegalArgumentException("Unknown access");
    }

    @Nonnull
    public static List<String> getNames()
    {
        List<String> names = new ArrayList<>();
        for (Permission permission : Permission.values())
        {
            if (permission != Permission.UNKNOWN)
                names.add(permission.getName());
        }
        return names;
    }
}
