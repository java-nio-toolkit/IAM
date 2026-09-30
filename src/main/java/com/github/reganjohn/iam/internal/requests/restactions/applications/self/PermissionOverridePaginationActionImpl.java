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

package com.github.reganjohn.iam.internal.requests.restactions.applications.self;

import com.github.adamorgan.jnt.api.requests.MediaType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.responsebody.BufferedResponseBody;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.entities.PermissionOverride;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.api.requests.restactions.applications.self.PermissionOverridePaginationAction;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractApplicationActionImpl;
import io.netty.channel.ChannelHandlerContext;
import org.apache.commons.collections4.map.CaseInsensitiveMap;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.UUID;

public class PermissionOverridePaginationActionImpl extends AbstractApplicationActionImpl implements PermissionOverridePaginationAction
{
    public static final MediaType MEDIA_TYPE_JSON = MediaType.parse("application/json; charset=utf-8");

    public PermissionOverridePaginationActionImpl(@Nonnull IAMImpl api)
    {
        super(api, Routes.Applications.GET_ENTITLEMENTS);
    }

    @Override
    public void handleRequest(@Nonnull ChannelHandlerContext context, @Nonnull Request request)
    {
        UUID userId = retrieveSelfUserId(context);
        api.retrieveUserById(userId)
                .flatMap(User::retrieveEntitlements)
                .map(this::mapFromData).queue(json -> handleSuccess(context, json), context::fireExceptionCaught);
    }

    @Nonnull
    private DataArray mapFromData(@Nonnull List<PermissionOverride> data)
    {
        return data.stream().map(this::mapFromData).collect(Helpers.toDataArray());
    }

    @Nonnull
    private DataObject mapFromData(@Nonnull PermissionOverride entitlement)
    {
        return DataObject.empty()
                .put("user_id", entitlement.getUserId())
                .put("application_id", entitlement.getApplicationId())
                .put("permissions", entitlement.getPermissionsRaw())
                .put("updated_at", entitlement.getTimeUpdated().toInstant().toEpochMilli())
                .toData();
    }

    private void handleSuccess(@Nonnull ChannelHandlerContext context, @Nonnull DataArray successObj)
    {
        BufferedResponseBody body = new BufferedResponseBody(MEDIA_TYPE_JSON, successObj.toBinary(), true);
        context.writeAndFlush(new Response(context, StatusReason.OK, new CaseInsensitiveMap<>(), body));
    }
}
