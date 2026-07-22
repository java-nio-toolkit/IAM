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

package com.github.reganjohn.iam.internal.managers;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.adamorgan.jnt.api.exceptions.PermissionException;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Route;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataType;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ClassicObjectManagerImpl;
import com.github.reganjohn.iam.api.Permission;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.exceptions.InsufficientPermissionException;
import com.github.reganjohn.iam.api.managers.PermOverrideManager;
import com.github.reganjohn.iam.api.requests.Routes;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class PermOverrideManagerImpl extends ClassicObjectManagerImpl implements PermOverrideManager
{
    private static final CaseInsensitiveMap<String, Permission> PERMISSIONS = new CaseInsensitiveMap<>(toPermMap());

    @Override
    public void channelRead0(@Nonnull ChannelHandlerContext context, @Nonnull Request request) throws Exception
    {
        AccessObjectData data = context.channel().attr(AccessOverrideManagerImpl.CONTEXT).get();
        if (data == null || data.getActor() == null)
            context.fireChannelRead(request);
        else if (!data.getBody().hasKey("access", DataType.ARRAY))
            throw new ErrorResponseException(ErrorResponse.MISSING_ACCESS);
        else
            handlePermissions(context, request, getPermissions(data));
    }

    private void handlePermissions(@Nonnull ChannelHandlerContext context, @Nonnull Request request,
                                   @Nonnull EnumSet<Permission> permissions) throws PermissionException
    {
        Route route = request.getRoute().getBaseRoute();
        if (route == Routes.Self.GET_SELF && permissions.contains(Permission.VIEW_ACCOUNT))
            context.fireChannelRead(request);
        else if (route.isInteraction())
            context.fireChannelRead(request);
        else
            throw new InsufficientPermissionException();
    }

    @Nonnull
    private EnumSet<Permission> getPermissions(@Nonnull AccessObjectData data)
    {
        DataArray array = data.getBody().getArray("access");
        EnumSet<Permission> permissions = EnumSet.noneOf(Permission.class);
        for (JsonNode json : array)
        {
            String type = json.get("type").asText();
            for (JsonNode action : json.get("actions"))
            {
                Permission permission = PERMISSIONS.get(type + "." + action.asText());
                if (permission != null)
                    permissions.add(permission);
            }
        }

        return permissions;
    }

    @Nonnull
    private static Map<String, Permission> toPermMap()
    {
        return Arrays.stream(Permission.values()).collect(Collectors.toUnmodifiableMap(Permission::getName, Function.identity()));
    }

    @Override
    public boolean isSharable()
    {
        return true;
    }
}
