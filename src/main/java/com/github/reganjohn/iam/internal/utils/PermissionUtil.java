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

import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.Permission;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;

import javax.annotation.Nonnull;
import java.util.EnumSet;
import java.util.LinkedHashMap;
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
}
